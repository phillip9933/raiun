package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.AuthTokens
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Validates an OAuth token response before it can replace a usable persisted grant. */
internal fun parseOAuthTokenResponse(
    body: String,
    nowEpochSeconds: Long,
    json: Json,
): AuthTokens {
    val data =
        try {
            json.parseToJsonElement(body) as? JsonObject ?: invalidTokenResponse()
        } catch (_: SerializationException) {
            invalidTokenResponse()
        }
    val lifetime = data.tokenLifetime()
    val expiry =
        try {
            Math.addExact(nowEpochSeconds, lifetime.coerceAtMost(MAX_TOKEN_LIFETIME_SECONDS))
        } catch (_: ArithmeticException) {
            invalidTokenResponse()
        }
    return AuthTokens(
        accessToken = data.tokenString("access_token", required = true)!!,
        refreshToken = data.tokenString("refresh_token"),
        expiresAtEpochSeconds = expiry,
        tokenType = data.tokenString("token_type", required = true)!!,
        scope = data.tokenScope(),
    ).also { it.bearerAuthorizationHeader() }
}

private fun JsonObject.tokenString(
    name: String,
    required: Boolean = false,
): String? {
    val element = get(name)
    if (element == null || element == JsonNull) {
        if (required) invalidTokenResponse()
        return null
    }
    val primitive = element as? JsonPrimitive ?: invalidTokenResponse()
    if (!primitive.isString) invalidTokenResponse()
    return primitive.content.takeIf { value -> value.isNotBlank() && value.all { it.code in 0x20..0x7e } }
        ?: invalidTokenResponse()
}

private fun JsonObject.tokenLifetime(): Long {
    val element = get("expires_in") ?: return DEFAULT_TOKEN_LIFETIME_SECONDS
    val primitive = element as? JsonPrimitive ?: invalidTokenResponse()
    val text = primitive.content
    // Also accept integer strings used by some providers, without accepting malformed values as defaults.
    if (text.isEmpty() || text.any { it !in '0'..'9' }) invalidTokenResponse()
    return text.toLongOrNull() ?: invalidTokenResponse()
}

private fun JsonObject.tokenScope(): String? {
    val element = get("scope")
    if (element == null || element == JsonNull) return null
    val primitive = element as? JsonPrimitive ?: invalidTokenResponse()
    if (!primitive.isString) invalidTokenResponse()
    val scope = primitive.content
    if (scope.split(' ').any(String::isEmpty) || scope.any { it.code !in 0x20..0x7e || it in "\"\\" }) {
        invalidTokenResponse()
    }
    return scope
}

private fun invalidTokenResponse(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

private const val DEFAULT_TOKEN_LIFETIME_SECONDS = 3600L
private const val MAX_TOKEN_LIFETIME_SECONDS = 31536000L
