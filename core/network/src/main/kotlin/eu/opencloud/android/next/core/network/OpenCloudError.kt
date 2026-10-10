package eu.opencloud.android.next.core.network

import android.content.Context
import java.io.FileNotFoundException
import java.io.IOException
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.time.Clock
import java.time.Duration
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException
import java.util.concurrent.CancellationException
import javax.net.ssl.SSLException

/** Safe domain failures: never retain response text, URLs, headers or original exceptions. */
sealed interface OpenCloudError {
    data object Connectivity : OpenCloudError

    data object Timeout : OpenCloudError

    data object AuthenticationRequired : OpenCloudError

    data object ClientRegistrationRequired : OpenCloudError

    data object AccessDenied : OpenCloudError

    data object PublicLinkPasswordRequired : OpenCloudError

    data class ShareRejected(
        val reason: ShareRejection,
        val passwordMinimums: Map<PasswordCharacterClass, Int> = emptyMap(),
    ) : OpenCloudError

    data object NotFound : OpenCloudError

    data object Conflict : OpenCloudError

    data object PreconditionFailed : OpenCloudError

    data object DownloadIntegrity : OpenCloudError

    data object InvalidResponse : OpenCloudError

    data object QuotaExceeded : OpenCloudError

    data object LocalStorage : OpenCloudError

    data object SourceUnavailable : OpenCloudError

    data object SourcePermissionDenied : OpenCloudError

    data object Unsupported : OpenCloudError

    data object Trust : OpenCloudError

    data object Unknown : OpenCloudError

    data class NotReady(
        val retryAfterSeconds: Long?,
    ) : OpenCloudError

    data class RateLimited(
        val retryAfterSeconds: Long?,
    ) : OpenCloudError

    data class ServerFailure(
        val statusCode: Int,
        val retryAfterSeconds: Long?,
    ) : OpenCloudError

    data class HttpFailure(
        val statusCode: Int,
    ) : OpenCloudError
}

enum class ShareRejection {
    PASSWORD_POLICY,
    PERMISSIONS,
    RESOURCE_REFERENCE,
    SPACE_ROOT,
    EXPIRATION,
    REQUEST_FORMAT,
    UNKNOWN,
}

enum class PasswordCharacterClass(
    val label: String,
) {
    LENGTH("characters"),
    LOWERCASE("lowercase letters"),
    UPPERCASE("uppercase letters"),
    DIGITS("numbers"),
    SPECIAL("special characters"),
}

private fun passwordPolicyMessage(minimums: Map<PasswordCharacterClass, Int>): String {
    val requirements = minimums.entries.joinToString("; ") { (kind, count) -> "at least $count ${kind.label}" }
    return if (requirements.isEmpty()) {
        "The link password does not meet the server's password rules."
    } else {
        "The link password needs: $requirements."
    }
}

open class OpenCloudException(
    val error: OpenCloudError,
) : IllegalStateException(error.safeMessage())

/** Cancellation is control flow; callers must not persist it or turn it into retry/failure. */
fun Throwable.toOpenCloudError(): OpenCloudError =
    when (this) {
        is CancellationException -> throw this
        is OpenCloudException -> error
        is SocketTimeoutException -> OpenCloudError.Timeout
        is UnknownHostException, is ConnectException -> OpenCloudError.Connectivity
        is SSLException -> OpenCloudError.Trust
        is SecurityException -> OpenCloudError.SourcePermissionDenied
        is FileNotFoundException -> OpenCloudError.SourceUnavailable
        // An arbitrary IOException can be local disk I/O. It is not evidence of connectivity failure.
        is IOException -> OpenCloudError.Unknown
        else -> OpenCloudError.Unknown
    }

fun httpError(
    statusCode: Int,
    retryAfterSeconds: Long? = null,
): OpenCloudError =
    when (statusCode) {
        401 -> OpenCloudError.AuthenticationRequired
        403 -> OpenCloudError.AccessDenied
        404 -> OpenCloudError.NotFound
        409 -> OpenCloudError.Conflict
        412 -> OpenCloudError.PreconditionFailed
        425 -> OpenCloudError.NotReady(retryAfterSeconds)
        429 -> OpenCloudError.RateLimited(retryAfterSeconds)
        507 -> OpenCloudError.QuotaExceeded
        501 -> OpenCloudError.Unsupported
        in 500..599 -> OpenCloudError.ServerFailure(statusCode, retryAfterSeconds)
        else -> OpenCloudError.HttpFailure(statusCode)
    }

/** RFC 9110 delay-seconds or HTTP-date. Invalid values are absent, never echoed to diagnostics. */
@Suppress("ReturnCount")
fun parseRetryAfter(
    value: String?,
    clock: Clock = Clock.systemUTC(),
): Long? {
    val text = value?.trim()?.takeIf(String::isNotEmpty) ?: return null
    if (text.all { it in '0'..'9' }) return text.toLongOrNull() ?: Long.MAX_VALUE
    return try {
        val deadline = ZonedDateTime.parse(text, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant()
        val remaining = Duration.between(clock.instant(), deadline)
        if (remaining.isNegative) 0 else remaining.seconds + if (remaining.nano > 0) 1 else 0
    } catch (_: DateTimeParseException) {
        null
    }
}

// Exhaustive presentation mapping, with no input-derived strings except numeric status codes.
@Suppress("CyclomaticComplexMethod")
fun OpenCloudError.safeMessage(): String =
    when (this) {
        OpenCloudError.Connectivity -> "The server could not be reached."
        OpenCloudError.Timeout -> "The connection timed out."
        OpenCloudError.AuthenticationRequired -> "Sign in again to continue."
        OpenCloudError.ClientRegistrationRequired ->
            "A valid sign-in client registration is required. Ask your administrator for a mobile client ID."
        OpenCloudError.AccessDenied -> "Access was denied."
        OpenCloudError.PublicLinkPasswordRequired -> "This server requires a password for public links."
        is OpenCloudError.ShareRejected ->
            when (reason) {
                ShareRejection.PASSWORD_POLICY -> passwordPolicyMessage(passwordMinimums)
                ShareRejection.PERMISSIONS -> "The server rejected the requested sharing permissions."
                ShareRejection.RESOURCE_REFERENCE -> "The server could not resolve the file's sharing reference."
                ShareRejection.SPACE_ROOT -> "The server does not allow sharing this personal space root."
                ShareRejection.EXPIRATION -> "The server rejected the link expiration date."
                ShareRejection.REQUEST_FORMAT -> "The server could not read the sharing request."
                ShareRejection.UNKNOWN -> "The server rejected the sharing request (HTTP 400; unrecognized reason)."
            }
        OpenCloudError.NotFound -> "The remote item was not found."
        OpenCloudError.Conflict -> "An item with this name already exists."
        OpenCloudError.PreconditionFailed -> "The remote item changed. Refresh before trying again."
        OpenCloudError.DownloadIntegrity -> "The downloaded file could not be verified. Try downloading it again."
        OpenCloudError.InvalidResponse -> "The server returned incomplete or unexpected metadata."
        OpenCloudError.QuotaExceeded -> "The server has insufficient storage."
        OpenCloudError.LocalStorage -> "The device has insufficient storage."
        OpenCloudError.SourceUnavailable -> "The selected file is no longer available."
        OpenCloudError.SourcePermissionDenied -> "Permission to read the selected file was lost."
        OpenCloudError.Unsupported -> "The server does not support this operation."
        OpenCloudError.Trust -> "The secure connection could not be verified."
        OpenCloudError.Unknown -> "The operation could not be completed."
        is OpenCloudError.NotReady -> "The server is still preparing this file. Retrying shortly."
        is OpenCloudError.RateLimited -> "The server is busy. Try again later."
        is OpenCloudError.ServerFailure -> "The server returned HTTP $statusCode."
        is OpenCloudError.HttpFailure -> "The server returned HTTP $statusCode."
    }

/** UI presentation mapping. Only fixed resources and typed numeric values are exposed. */
@Suppress("CyclomaticComplexMethod")
fun OpenCloudError.safeMessage(context: Context): String =
    when (this) {
        OpenCloudError.Connectivity -> context.getString(R.string.error_connectivity)
        OpenCloudError.Timeout -> context.getString(R.string.error_timeout)
        OpenCloudError.AuthenticationRequired -> context.getString(R.string.error_authentication_required)
        OpenCloudError.ClientRegistrationRequired -> context.getString(R.string.error_client_registration_required)
        OpenCloudError.AccessDenied -> context.getString(R.string.error_access_denied)
        OpenCloudError.PublicLinkPasswordRequired -> context.getString(R.string.error_public_link_password_required)
        is OpenCloudError.ShareRejected ->
            when (reason) {
                ShareRejection.PASSWORD_POLICY -> localizedPasswordPolicyMessage(context, passwordMinimums)
                ShareRejection.PERMISSIONS -> context.getString(R.string.error_share_permissions)
                ShareRejection.RESOURCE_REFERENCE -> context.getString(R.string.error_share_resource_reference)
                ShareRejection.SPACE_ROOT -> context.getString(R.string.error_share_space_root)
                ShareRejection.EXPIRATION -> context.getString(R.string.error_share_expiration)
                ShareRejection.REQUEST_FORMAT -> context.getString(R.string.error_share_request_format)
                ShareRejection.UNKNOWN -> context.getString(R.string.error_share_unknown)
            }
        OpenCloudError.NotFound -> context.getString(R.string.error_not_found)
        OpenCloudError.Conflict -> context.getString(R.string.error_conflict)
        OpenCloudError.PreconditionFailed -> context.getString(R.string.error_precondition_failed)
        OpenCloudError.DownloadIntegrity -> context.getString(R.string.error_download_integrity)
        OpenCloudError.InvalidResponse -> context.getString(R.string.error_invalid_response)
        OpenCloudError.QuotaExceeded -> context.getString(R.string.error_quota_exceeded)
        OpenCloudError.LocalStorage -> context.getString(R.string.error_local_storage)
        OpenCloudError.SourceUnavailable -> context.getString(R.string.error_source_unavailable)
        OpenCloudError.SourcePermissionDenied -> context.getString(R.string.error_source_permission_denied)
        OpenCloudError.Unsupported -> context.getString(R.string.error_unsupported)
        OpenCloudError.Trust -> context.getString(R.string.error_trust)
        OpenCloudError.Unknown -> context.getString(R.string.error_unknown)
        is OpenCloudError.NotReady -> context.getString(R.string.error_not_ready)
        is OpenCloudError.RateLimited -> context.getString(R.string.error_rate_limited)
        is OpenCloudError.ServerFailure -> context.getString(R.string.error_http_status, statusCode)
        is OpenCloudError.HttpFailure -> context.getString(R.string.error_http_status, statusCode)
    }

private fun localizedPasswordPolicyMessage(
    context: Context,
    minimums: Map<PasswordCharacterClass, Int>,
): String {
    val requirements =
        minimums.entries
            .sortedBy { it.key.ordinal }
            .joinToString(context.getString(R.string.error_password_policy_separator)) { (kind, count) ->
                val label =
                    when (kind) {
                        PasswordCharacterClass.LENGTH -> context.getString(R.string.error_password_characters)
                        PasswordCharacterClass.LOWERCASE -> context.getString(R.string.error_password_lowercase)
                        PasswordCharacterClass.UPPERCASE -> context.getString(R.string.error_password_uppercase)
                        PasswordCharacterClass.DIGITS -> context.getString(R.string.error_password_numbers)
                        PasswordCharacterClass.SPECIAL -> context.getString(R.string.error_password_special)
                    }
                context.getString(R.string.error_password_requirement, count, label)
            }
    return if (requirements.isEmpty()) {
        context.getString(R.string.error_password_policy)
    } else {
        context.getString(R.string.error_password_policy_with_requirements, requirements)
    }
}
