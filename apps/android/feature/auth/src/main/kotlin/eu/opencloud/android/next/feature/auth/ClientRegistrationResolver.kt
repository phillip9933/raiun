package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.model.auth.ClientRegistrationSource
import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.CredentialStore
import java.security.MessageDigest

/** Cached binding, advertised client, public DCR, then an explicitly supplied static client. */
class ClientRegistrationResolver(
    private val api: OpenCloudApi,
    private val credentials: CredentialStore,
) {
    fun resolve(
        serverUrl: String,
        configuration: OidcConfiguration,
        staticClientId: String? = null,
    ): OidcConfiguration {
        val key = key(serverUrl, configuration)
        val advertisedClientId = configuration.clientId
        val requestedStaticClientId =
            staticClientId?.takeIf {
                it.isNotBlank() &&
                    advertisedClientId.isNullOrBlank() &&
                    configuration.registrationEndpoint == null
            }
        val cached =
            credentials.readClientRegistration(key)?.takeIf {
                matches(it, serverUrl, configuration) &&
                    (configuration.clientId.isNullOrBlank() || configuration.clientId == it.clientId) &&
                    (requestedStaticClientId == null || requestedStaticClientId == it.clientId)
            }
        val registration =
            cached ?: when {
                !advertisedClientId.isNullOrBlank() ->
                    binding(
                        serverUrl,
                        configuration,
                        advertisedClientId,
                        ClientRegistrationSource.ADVERTISED,
                    )
                configuration.registrationEndpoint != null -> api.registerClient(serverUrl, configuration)
                !staticClientId.isNullOrBlank() ->
                    binding(
                        serverUrl,
                        configuration,
                        staticClientId,
                        ClientRegistrationSource.STATIC,
                    )
                else -> throw OpenCloudException(OpenCloudError.ClientRegistrationRequired)
            }
        if (cached == null) credentials.saveClientRegistration(key, registration)
        return configuration.copy(clientId = registration.clientId)
    }

    fun bindingForSession(
        serverUrl: String,
        configuration: OidcConfiguration,
    ): OidcClientRegistration {
        val registration = credentials.readClientRegistration(key(serverUrl, configuration))
        if (registration == null ||
            !matches(registration, serverUrl, configuration) ||
            registration.clientId != configuration.clientId
        ) {
            throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        }
        return registration
    }

    private fun matches(
        value: OidcClientRegistration,
        serverUrl: String,
        configuration: OidcConfiguration,
    ): Boolean =
        value.serverUrl == serverUrl &&
            value.issuer == configuration.issuer &&
            value.redirectUri == NEXT_OIDC_REDIRECT_URI &&
            value.tokenEndpoint == configuration.tokenEndpoint &&
            value.authorizationEndpoint == configuration.authorizationEndpoint

    private fun binding(
        serverUrl: String,
        configuration: OidcConfiguration,
        clientId: String,
        source: ClientRegistrationSource,
    ): OidcClientRegistration {
        if (clientId.isBlank() || clientId.any(Char::isISOControl)) throw OpenCloudException(OpenCloudError.Unsupported)
        return OidcClientRegistration(
            serverUrl,
            configuration.issuer,
            clientId,
            NEXT_OIDC_REDIRECT_URI,
            configuration.authorizationEndpoint,
            configuration.tokenEndpoint,
            source,
        )
    }

    private fun key(
        serverUrl: String,
        configuration: OidcConfiguration,
    ): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(
                listOf(
                    serverUrl,
                    configuration.issuer,
                    NEXT_OIDC_REDIRECT_URI,
                    configuration.authorizationEndpoint,
                    configuration.tokenEndpoint,
                    configuration.registrationEndpoint.orEmpty(),
                ).joinToString("\u0000")
                    .toByteArray(Charsets.UTF_8),
            ).joinToString("") { "%02x".format(it) }
}
