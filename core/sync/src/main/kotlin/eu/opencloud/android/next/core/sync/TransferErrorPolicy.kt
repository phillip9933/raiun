package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.OpenCloudError

/** Refused or unsent requests only; ambiguous timeout/server failures require reconciliation. */
internal fun OpenCloudError.canRetryTransfer(attempt: Int): Boolean =
    attempt < 5 &&
        (this == OpenCloudError.Connectivity || this is OpenCloudError.RateLimited || this is OpenCloudError.NotReady)

/** Retry ambiguous network outcomes only when replay cannot replace a newer remote file. */
internal fun OpenCloudError.canRetryTransfer(transfer: TransferEntity): Boolean {
    if (canRetryTransfer(transfer.attemptCount)) return true
    val guarded =
        transfer.direction == "DOWNLOAD" ||
            !transfer.overwrite ||
            transfer.expectedETag != null ||
            transfer.verificationPending
    val transient =
        this == OpenCloudError.Timeout ||
            (this is OpenCloudError.ServerFailure && statusCode in setOf(500, 502, 503, 504))
    return transfer.attemptCount < 5 && guarded && transient
}

internal fun OpenCloudError.retryDeadline(now: Long): Long {
    val seconds =
        (
            (this as? OpenCloudError.RateLimited)?.retryAfterSeconds
                ?: (this as? OpenCloudError.NotReady)?.retryAfterSeconds
                ?: (this as? OpenCloudError.ServerFailure)?.retryAfterSeconds ?: 30L
        ).coerceAtLeast(0)
    return if (seconds > (Long.MAX_VALUE - now) / 1000) Long.MAX_VALUE else now + seconds * 1000
}

@Suppress("CyclomaticComplexMethod")
internal fun OpenCloudError.diagnosticCode(): String =
    when (this) {
        OpenCloudError.Connectivity -> "CONNECTIVITY"
        OpenCloudError.Timeout -> "TIMEOUT"
        OpenCloudError.AuthenticationRequired -> "AUTHENTICATION_REQUIRED"
        OpenCloudError.ClientRegistrationRequired -> "CLIENT_REGISTRATION_REQUIRED"
        OpenCloudError.AccessDenied -> "ACCESS_DENIED"
        OpenCloudError.PublicLinkPasswordRequired -> "PASSWORD_REQUIRED"
        is OpenCloudError.ShareRejected -> "SHARE_${reason.name}"
        OpenCloudError.NotFound -> "NOT_FOUND"
        OpenCloudError.Conflict -> "CONFLICT"
        OpenCloudError.PreconditionFailed -> "PRECONDITION_FAILED"
        OpenCloudError.DownloadIntegrity -> "DOWNLOAD_INTEGRITY"
        OpenCloudError.InvalidResponse -> "INVALID_RESPONSE"
        OpenCloudError.QuotaExceeded -> "REMOTE_QUOTA"
        OpenCloudError.LocalStorage -> "LOCAL_STORAGE"
        OpenCloudError.SourceUnavailable -> "SOURCE_UNAVAILABLE"
        OpenCloudError.SourcePermissionDenied -> "SOURCE_PERMISSION"
        OpenCloudError.Unsupported -> "UNSUPPORTED"
        OpenCloudError.Trust -> "TRUST"
        OpenCloudError.Unknown -> "UNKNOWN"
        is OpenCloudError.NotReady -> "REMOTE_NOT_READY"
        is OpenCloudError.RateLimited -> "RATE_LIMITED"
        is OpenCloudError.ServerFailure -> "SERVER_$statusCode"
        is OpenCloudError.HttpFailure -> "HTTP_$statusCode"
    }
