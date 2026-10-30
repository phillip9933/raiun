package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.PendingOidcLogin
import java.net.URI
import java.net.URISyntaxException
import java.net.URLDecoder

internal class OidcCallbackIssuerException : IllegalStateException("The sign-in issuer could not be verified.")

internal sealed interface OidcCallbackResult<out T> {
    data object Expired : OidcCallbackResult<Nothing>

    data object Rejected : OidcCallbackResult<Nothing>

    data class Completed<T>(
        val value: T,
    ) : OidcCallbackResult<T>
}

/** Check every supplied response issuer, and require it when the provider advertises RFC 9207. */
internal fun <T> processOidcCallback(
    callback: String,
    consumePending: (String) -> PendingOidcLogin?,
    exchange: (PendingOidcLogin, String) -> T,
): OidcCallbackResult<T> {
    val parameters = callbackParameters(callback)
    val states = parameters["state"].orEmpty()
    if (states.size != 1 || states.single().isBlank()) invalidCallback()
    val pending = consumePending(states.single()) ?: return OidcCallbackResult.Expired
    validateCallbackIssuer(parameters["iss"].orEmpty(), pending)
    val codes = parameters["code"].orEmpty()
    return if ("error" in parameters || codes.size != 1 || codes.single().isBlank()) {
        OidcCallbackResult.Rejected
    } else {
        OidcCallbackResult.Completed(exchange(pending, codes.single()))
    }
}

private fun validateCallbackIssuer(
    issuers: List<String>,
    pending: PendingOidcLogin,
) {
    if (issuers.isEmpty() && !pending.configuration.authorizationResponseIssParameterSupported) return
    if (issuers.size != 1 || issuers.single().isBlank() || issuers.single() != pending.configuration.issuer) {
        throw OidcCallbackIssuerException()
    }
}

private fun callbackParameters(callback: String): Map<String, List<String>> {
    val uri =
        try {
            URI(callback)
        } catch (_: URISyntaxException) {
            invalidCallback()
        }
    val correctEndpoint = uri.scheme == NEXT_OIDC_REDIRECT_URI.substringBefore("://") && uri.rawAuthority == "oauth"
    val queryOnly = uri.rawPath.isNullOrEmpty() && uri.rawFragment == null
    if (!correctEndpoint || !queryOnly) {
        invalidCallback()
    }
    return try {
        uri.rawQuery
            .orEmpty()
            .split('&')
            .map { parameter ->
                URLDecoder.decode(parameter.substringBefore('='), "UTF-8") to
                    URLDecoder.decode(parameter.substringAfter('=', ""), "UTF-8")
            }.groupBy({ it.first }, { it.second })
    } catch (_: IllegalArgumentException) {
        invalidCallback()
    }
}

private fun invalidCallback(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)
