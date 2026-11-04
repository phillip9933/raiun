package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.AuthTokens

/**
 * Formats the only OAuth authorization scheme currently supported by Raiun.
 * Token values are kept opaque and byte-for-byte, but must not contain HTTP
 * header controls that could alter the request.
 */
fun AuthTokens.bearerAuthorizationHeader(): String {
    if (!tokenType.equals("Bearer", ignoreCase = true) || tokenType.isBlank()) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
    // RFC 6750 b64token: padding may occur only after the opaque token body.
    val body = accessToken.trimEnd('=')
    if (body.isEmpty() || body.any { it !in BEARER_TOKEN_BODY_CHARACTERS }) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
    return "Bearer $accessToken"
}

private const val BEARER_TOKEN_BODY_CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/"
