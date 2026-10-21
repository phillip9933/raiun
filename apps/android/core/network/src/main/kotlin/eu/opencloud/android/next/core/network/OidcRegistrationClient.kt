package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.ClientRegistrationSource
import eu.opencloud.android.next.core.model.auth.NEXT_OIDC_REDIRECT_URI
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

class OidcRegistrationClient(
    client: OkHttpClient,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
            .withMetadataDeadline()
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

    fun register(
        serverUrl: String,
        configuration: OidcConfiguration,
    ): OidcClientRegistration {
        val endpoint = configuration.registrationEndpoint ?: unsupported()
        val request =
            Request
                .Builder()
                .url(endpoints.endpoint(endpoint))
                .post(json.encodeToString(RegistrationRequest()).toRequestBody("application/json".toMediaType()))
                .build()
        return client.newCall(request).execute().use { response ->
            if (response.code != 201) throw TransferHttpException(response.code)
            val metadata =
                try {
                    json.decodeFromString<RegistrationResponse>(response.readBoundedMetadata(AUTH_METADATA_LIMIT_BYTES))
                } catch (_: kotlinx.serialization.SerializationException) {
                    unsupported()
                }
            if (metadata.clientId.isBlank() || metadata.clientId.any(Char::isISOControl)) unsupported()
            if (metadata.redirectUris != listOf(NEXT_OIDC_REDIRECT_URI) ||
                metadata.authMethod != "none" ||
                metadata.responseTypes != listOf("code")
            ) {
                unsupported()
            }
            if ("authorization_code" !in metadata.grantTypes ||
                metadata.grantTypes.any { it !in setOf("authorization_code", "refresh_token") }
            ) {
                unsupported()
            }
            metadata.registrationClientUri?.let { endpoints.endpoint(it) }
            OidcClientRegistration(
                serverUrl,
                configuration.issuer,
                metadata.clientId,
                NEXT_OIDC_REDIRECT_URI,
                configuration.authorizationEndpoint,
                configuration.tokenEndpoint,
                ClientRegistrationSource.DYNAMIC,
                metadata.registrationAccessToken,
                metadata.registrationClientUri,
            )
        }
    }

    private fun unsupported(): Nothing = throw OpenCloudException(OpenCloudError.Unsupported)
}

@Serializable
private data class RegistrationRequest(
    @SerialName("client_name") val name: String = "Raiun",
    @SerialName("application_type") val applicationType: String = "native",
    @SerialName("redirect_uris") val redirectUris: List<String> = listOf(NEXT_OIDC_REDIRECT_URI),
    @SerialName("grant_types") val grantTypes: List<String> = listOf("authorization_code", "refresh_token"),
    @SerialName("response_types") val responseTypes: List<String> = listOf("code"),
    @SerialName("token_endpoint_auth_method") val authMethod: String = "none",
)

@Serializable
private data class RegistrationResponse(
    @SerialName("client_id") val clientId: String,
    @SerialName("redirect_uris") val redirectUris: List<String> = emptyList(),
    @SerialName("grant_types") val grantTypes: List<String> = emptyList(),
    @SerialName("response_types") val responseTypes: List<String> = emptyList(),
    @SerialName("token_endpoint_auth_method") val authMethod: String? = null,
    @SerialName("registration_access_token") val registrationAccessToken: String? = null,
    @SerialName("registration_client_uri") val registrationClientUri: String? = null,
)
