package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.model.auth.PkceRequest
import org.json.JSONArray

data class PendingOidcLogin(
    val serverUrl: String,
    val configuration: OidcConfiguration,
    val request: PkceRequest,
    val createdAt: Long,
) {
    fun validAt(now: Long): Boolean = now >= createdAt && now - createdAt <= 10 * 60 * 1000L

    internal fun encode(): String =
        JSONArray(
            listOf(
                serverUrl,
                configuration.issuer,
                configuration.authorizationEndpoint,
                configuration.tokenEndpoint,
                configuration.registrationEndpoint.orEmpty(),
                configuration.clientId.orEmpty(),
                JSONArray(configuration.scopes),
                request.authorizationUrl,
                request.state,
                request.codeVerifier,
                createdAt,
                configuration.authorizationResponseIssParameterSupported,
            ),
        ).toString()

    companion object {
        internal fun decode(serialized: String): PendingOidcLogin {
            require(serialized.length <= 64 * 1024)
            val values = JSONArray(serialized)
            require(values.length() in 11..12)
            val scopes = values.getJSONArray(6)
            val issuerResponseSupported = if (values.length() == 12) values.get(11) else false
            require(issuerResponseSupported is Boolean)
            return PendingOidcLogin(
                values.getString(0),
                OidcConfiguration(
                    values.getString(1),
                    values.getString(2),
                    values.getString(3),
                    values.getString(4).ifBlank { null },
                    values.getString(5),
                    (0 until scopes.length()).map(scopes::getString),
                    issuerResponseSupported,
                ),
                PkceRequest(values.getString(7), values.getString(8), values.getString(9)),
                values.getLong(10),
            )
        }
    }
}
