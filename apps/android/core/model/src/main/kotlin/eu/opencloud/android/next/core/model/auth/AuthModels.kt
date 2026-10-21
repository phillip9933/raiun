package eu.opencloud.android.next.core.model.auth

const val OPEN_CLOUD_ANDROID_OIDC_CLIENT_ID = "OpenCloudAndroid"

data class Account(
    val id: String,
    val serverUrl: String,
    val userId: String,
    val displayName: String,
    val authenticationType: AuthenticationType,
)

enum class AuthenticationType {
    BASIC,
    OIDC,
}

data class UserProfile(
    val id: String,
    val displayName: String,
    val email: String?,
)

data class ServerCapabilities(
    val version: String?,
    val sharingEnabled: Boolean,
    val publicSharingEnabled: Boolean,
    val spacesEnabled: Boolean,
    val tusSupported: Boolean,
    val remoteSearchUrl: String? = null,
    val trashSupported: Boolean = false,
    val publicLinkPasswordSupported: Boolean = false,
    val publicLinkPasswordEnforced: Boolean = false,
    val publicLinkExpirationSupported: Boolean = false,
    val publicLinkExpirationEnforced: Boolean = false,
    val publicLinkExpirationDays: Int? = null,
    val appProviders: List<ServerAppProvider> = emptyList(),
)

/** Advertised endpoints only; consumers must validate them before sending credentials. */
data class ServerAppProvider(
    val appsUrl: String,
    val openWebUrl: String?,
    val openUrl: String? = null,
)

data class OidcConfiguration(
    val issuer: String,
    val authorizationEndpoint: String,
    val tokenEndpoint: String,
    val registrationEndpoint: String?,
    val clientId: String?,
    val scopes: List<String>,
)

data class WebFingerMetadata(
    val issuer: String?,
    val clientId: String?,
    val scopes: List<String>?,
)

data class AuthTokens(
    val accessToken: String,
    val refreshToken: String?,
    val expiresAtEpochSeconds: Long,
    val tokenType: String,
    val scope: String?,
)

data class PkceRequest(
    val authorizationUrl: String,
    val state: String,
    val codeVerifier: String,
)
