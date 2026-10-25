package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.model.auth.Account
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.AuthenticationType
import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.model.auth.PkceRequest
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import eu.opencloud.android.next.core.model.auth.UserProfile
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.security.AccountSessions
import eu.opencloud.android.next.core.security.CredentialStore
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

class AuthRepository(
    private val api: OpenCloudApi,
    private val credentialStore: CredentialStore,
    private val sessions: AccountSessions = AccountSessions(credentialStore),
) {
    private val registrations = ClientRegistrationResolver(api, credentialStore)

    fun discover(
        serverInput: String,
        staticClientId: String? = null,
    ): DiscoveryResult =
        api.discover(serverInput).let { discovery ->
            val metadata = api.webFinger(discovery.canonicalServerUrl)
            val oidc =
                try {
                    registrations.resolve(
                        discovery.canonicalServerUrl,
                        api.oidcDiscovery(metadata?.issuer ?: discovery.canonicalServerUrl, metadata),
                        staticClientId,
                    )
                } catch (failure: eu.opencloud.android.next.core.network.TransferHttpException) {
                    if (failure.statusCode == 404 && metadata?.issuer == null) null else throw failure
                }
            DiscoveryResult(discovery.canonicalServerUrl, oidc)
        }

    fun loginBasic(
        serverUrl: String,
        username: String,
        password: String,
    ): AuthenticatedSession {
        val profile = api.basicProfile(serverUrl, username, password)
        val account =
            Account(
                accountId(serverUrl, profile.id),
                serverUrl,
                profile.id,
                profile.displayName,
                AuthenticationType.BASIC,
            )
        val authorization = okhttp3.Credentials.basic(username, password)
        val capabilities = api.capabilities(serverUrl, authorization)
        credentialStore.saveBasicCredentials(account.id, username, password)
        return AuthenticatedSession(account, profile, capabilities)
    }

    fun beginPkce(configuration: OidcConfiguration): PkceRequest {
        val state = randomUrlSafeValue()
        val verifier = randomUrlSafeValue()
        val challenge =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray()),
            )
        val authorizationUrl =
            configuration.authorizationEndpoint
                .toHttpUrl()
                .newBuilder()
                .addQueryParameter("response_type", "code")
                .addQueryParameter("prompt", "login")
                .addQueryParameter("client_id", requireNotNull(configuration.clientId))
                .addQueryParameter("redirect_uri", REDIRECT_URI)
                .addQueryParameter("scope", configuration.scopes.joinToString(" "))
                .addQueryParameter("state", state)
                .addQueryParameter("code_challenge", challenge)
                .addQueryParameter("code_challenge_method", "S256")
                .build()
                .toString()
        return PkceRequest(authorizationUrl, state, verifier)
    }

    fun completePkce(
        serverUrl: String,
        configuration: OidcConfiguration,
        code: String,
        verifier: String,
    ): AuthenticatedSession {
        val registration = registrations.bindingForSession(serverUrl, configuration)
        val tokens =
            try {
                api.exchangeCode(configuration, code, REDIRECT_URI, verifier)
            } catch (failure: eu.opencloud.android.next.core.network.OpenCloudException) {
                if (failure.error == eu.opencloud.android.next.core.network.OpenCloudError.ClientRegistrationRequired) {
                    credentialStore.invalidateClientRegistration(registration)
                }
                throw failure
            }
        val profile = api.bearerProfile(serverUrl, tokens.accessToken)
        val account =
            Account(
                accountId(serverUrl, profile.id),
                serverUrl,
                profile.id,
                profile.displayName,
                AuthenticationType.OIDC,
            )
        val capabilities = api.capabilities(serverUrl, "Bearer ${tokens.accessToken}")
        sessions.save(account.id, tokens, registration)
        return AuthenticatedSession(
            account,
            profile,
            capabilities,
            configuration,
        )
    }

    suspend fun refreshIfNeeded(
        account: Account,
        configuration: OidcConfiguration,
    ): AuthTokens =
        sessions.tokens(account.id) { current ->
            api.refresh(configuration, requireNotNull(current.refreshToken))
        }

    private fun accountId(
        serverUrl: String,
        userId: String,
    ): String = "${serverUrl.lowercase()}#$userId"

    private fun randomUrlSafeValue(): String =
        ByteArray(32).also(SecureRandom()::nextBytes).let {
            Base64.getUrlEncoder().withoutPadding().encodeToString(it)
        }

    private companion object {
        const val REDIRECT_URI = NEXT_OIDC_REDIRECT_URI
    }
}

data class DiscoveryResult(
    val serverUrl: String,
    val oidcConfiguration: OidcConfiguration?,
)

data class AuthenticatedSession(
    val account: Account,
    val profile: UserProfile,
    val capabilities: ServerCapabilities,
    val oidcConfiguration: OidcConfiguration? = null,
)
