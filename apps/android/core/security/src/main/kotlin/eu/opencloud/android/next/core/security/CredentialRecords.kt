package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.ClientRegistrationSource
import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import eu.opencloud.android.next.core.network.bearerAuthorizationHeader
import org.json.JSONArray
import java.net.URI

/** Validate a decrypted record before it can be returned or acquire a v2 envelope. */
internal object CredentialRecords {
    fun basic(value: String): String? = value.takeIf { it.isNotBlank() && it.length <= MAX_CHARS && '\u0000' !in it }

    fun tokens(value: String): AuthTokens? =
        checked {
            require(value.length <= MAX_CHARS)
            val fields = value.split('\u0000')
            require(fields.size == 5)
            require(fields[1].isEmpty() || fields[1].isNotBlank() && fields[1].all { it.code in 0x20..0x7e })
            val expiry = requireNotNull(fields[2].toLongOrNull())
            // Match the existing OAuth response scope grammar; the empty persisted field means absent scope.
            require(
                fields[4].isEmpty() ||
                    fields[4].split(' ').none(String::isEmpty) &&
                    fields[4].all {
                        it.code in 0x20..0x7e && it !in "\"\\"
                    },
            )
            AuthTokens(fields[0], fields[1].ifEmpty { null }, expiry, fields[3], fields[4].ifEmpty { null })
                .also { it.bearerAuthorizationHeader() }
        }

    fun registration(value: String): OidcClientRegistration? =
        checked {
            require(value.length <= MAX_CHARS)
            val values = JSONArray(value)
            require(values.length() == 9)
            val fields = (0..8).map { values.string(it) }
            require(listOf(0, 1, 4, 5).all { webUrl(fields[it]) })
            require(fields[2].isNotBlank() && fields[2].none(Char::isISOControl))
            require(fields[3] == NEXT_OIDC_REDIRECT_URI)
            require(fields[7].isEmpty() || token(fields[7]))
            require(fields[8].isEmpty() || webUrl(fields[8]))
            OidcClientRegistration(
                fields[0],
                fields[1],
                fields[2],
                fields[3],
                fields[4],
                fields[5],
                ClientRegistrationSource.valueOf(fields[6]),
                fields[7].ifEmpty { null },
                fields[8].ifEmpty { null },
            )
        }

    fun pending(value: String): PendingOidcLogin? =
        checked {
            require(value.length <= MAX_CHARS)
            val values = JSONArray(value)
            require(values.length() in 11..12)
            for (index in 0..5) values.string(index)
            for (index in 7..9) values.string(index)
            require(values.get(10) is Long || values.get(10) is Int)
            val scopes = values.getJSONArray(6)
            require(scopes.length() > 0)
            for (index in 0 until scopes.length()) require(scopes.string(index).isNotBlank())
            if (values.length() == 12) require(values.get(11) is Boolean)
            val login = PendingOidcLogin.decode(value)
            require(webUrl(login.serverUrl) && webUrl(login.configuration.issuer))
            require(webUrl(login.configuration.authorizationEndpoint) && webUrl(login.configuration.tokenEndpoint))
            require(login.configuration.registrationEndpoint?.let(::webUrl) != false)
            require(login.configuration.clientId?.isNotBlank() != false)
            require(webUrl(login.request.authorizationUrl) && token(login.request.state))
            require(
                login.request.codeVerifier.length in 43..128 &&
                    login.request.codeVerifier.all {
                        it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in "-._~"
                    },
            )
            require(login.createdAt >= 0)
            login
        }

    private fun JSONArray.string(index: Int): String = get(index).also { require(it is String) } as String

    private fun token(value: String): Boolean = value.isNotEmpty() && value.all { it.code in 33..126 }

    private fun webUrl(value: String): Boolean =
        URI(value).let {
            it.scheme in listOf("https", "http") &&
                !it.host.isNullOrBlank() &&
                it.rawUserInfo == null &&
                it.rawFragment == null
        }

    @Suppress("TooGenericExceptionCaught")
    private fun <T> checked(parse: () -> T): T? =
        try {
            parse()
        } catch (_: Exception) {
            null
        }

    private const val MAX_CHARS = 64 * 1024
}
