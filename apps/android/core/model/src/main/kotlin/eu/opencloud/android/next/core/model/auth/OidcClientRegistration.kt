package eu.opencloud.android.next.core.model.auth

const val NEXT_OIDC_REDIRECT_URI = "app.raiun.cloud://oauth"

enum class ClientRegistrationSource { ADVERTISED, DYNAMIC, STATIC }

/** Public client binding; optional registration-management credentials belong only in secure storage. */
data class OidcClientRegistration(
    val serverUrl: String,
    val issuer: String,
    val clientId: String,
    val redirectUri: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val source: ClientRegistrationSource,
    val registrationAccessToken: String? = null,
    val registrationClientUri: String? = null,
) {
    override fun toString(): String = "OidcClientRegistration([redacted], source=$source)"
}
