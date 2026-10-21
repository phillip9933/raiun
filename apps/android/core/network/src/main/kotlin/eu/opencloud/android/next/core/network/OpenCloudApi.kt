package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import eu.opencloud.android.next.core.model.auth.UserProfile
import eu.opencloud.android.next.core.model.auth.WebFingerMetadata
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Credentials
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request

class OpenCloudApi(
    client: OkHttpClient,
    private val json: Json = Json { ignoreUnknownKeys = true },
    private val endpoints: EndpointPolicy = EndpointPolicy(),
    private val clock: AppClock = SystemAppClock,
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
            .withMetadataDeadline()

    fun registerClient(
        serverUrl: String,
        configuration: OidcConfiguration,
    ) = OidcRegistrationClient(client, endpoints).register(serverUrl, configuration)

    fun discover(serverInput: String): DiscoveryResult {
        val normalized = normalizeServerUrl(serverInput)
        execute(
            Request
                .Builder()
                .url("$normalized/status.php")
                .get()
                .build(),
            consumeBody = false,
        )
        return DiscoveryResult(normalized)
    }

    fun webFinger(serverUrl: String): WebFingerMetadata? =
        runCatching {
            val endpoint =
                endpoints
                    .endpoint(serverUrl, allowQuery = false)
                    .newBuilder()
                    .addPathSegments(".well-known/webfinger")
                    .addQueryParameter("resource", serverUrl)
                    .addQueryParameter("rel", OIDC_ISSUER_REL)
                    .build()
            val root =
                bodyJson(
                    Request
                        .Builder()
                        .url(endpoint)
                        .get()
                        .build(),
                ).jsonObject
            val properties = root["properties"]?.jsonObject
            val links = root["links"]?.jsonArray.orEmpty()
            val issuer =
                (
                    links.firstOrNull { it.jsonObject["rel"]?.jsonPrimitive?.content == OIDC_ISSUER_REL }
                        ?: links.firstOrNull { it.jsonObject["rel"]?.jsonPrimitive?.content == LEGACY_ISSUER_REL }
                )?.jsonObject
                    ?.get("href")
                    ?.jsonPrimitive
                    ?.content
            WebFingerMetadata(
                issuer = issuer,
                clientId = properties?.get("http://opencloud.eu/ns/oidc/client_id")?.jsonPrimitive?.content,
                scopes =
                    properties
                        ?.get("http://opencloud.eu/ns/oidc/scopes")
                        ?.toString()
                        ?.trim('[', ']')
                        ?.split(',')
                        ?.map { it.trim().trim('"') }
                        ?.filter(String::isNotBlank),
            )
        }.getOrElse { failure ->
            if (failure is TransferHttpException && failure.statusCode == 404) null else throw failure
        }

    fun oidcDiscovery(
        issuer: String,
        webFinger: WebFingerMetadata?,
    ): OidcConfiguration {
        val expectedIssuer = endpoints.issuer(issuer)
        val root =
            bodyJson(
                Request
                    .Builder()
                    .url("${issuer.trimEnd('/')}/.well-known/openid-configuration")
                    .get()
                    .build(),
            ).jsonObject
        val scopes =
            webFinger?.scopes ?: root["scopes_supported"]
                ?.toString()
                ?.trim('[', ']')
                ?.split(',')
                ?.map { it.trim().trim('"') }
                ?.filter(String::isNotBlank)
                .orEmpty()
        if (endpoints.issuer(root.requiredString("issuer")) != expectedIssuer) {
            throw OpenCloudException(OpenCloudError.Trust)
        }
        return OidcConfiguration(
            issuer = expectedIssuer,
            authorizationEndpoint = endpoints.endpoint(root.requiredString("authorization_endpoint")).toString(),
            tokenEndpoint = endpoints.endpoint(root.requiredString("token_endpoint")).toString(),
            registrationEndpoint =
                root["registration_endpoint"]
                    ?.jsonPrimitive
                    ?.content
                    ?.let { endpoints.endpoint(it).toString() },
            clientId = webFinger?.clientId,
            scopes = scopes.ifEmpty { listOf("openid", "profile") },
        )
    }

    fun basicProfile(
        serverUrl: String,
        username: String,
        password: String,
    ): UserProfile = profile(serverUrl, Credentials.basic(username, password))

    fun bearerProfile(
        serverUrl: String,
        accessToken: String,
    ): UserProfile = profile(serverUrl, "Bearer $accessToken")

    fun capabilities(
        serverUrl: String,
        authorization: String,
    ): ServerCapabilities {
        val response =
            execute(
                Request
                    .Builder()
                    .url("$serverUrl/ocs/v1.php/cloud/capabilities?format=json")
                    .header("Authorization", authorization)
                    .header("OCS-APIREQUEST", "true")
                    .get()
                    .build(),
            )
        return CapabilitiesParser().parse(response.body, serverUrl)
    }

    fun exchangeCode(
        configuration: OidcConfiguration,
        code: String,
        redirectUri: String,
        codeVerifier: String,
    ): AuthTokens =
        tokenRequest(
            configuration.tokenEndpoint,
            FormBody
                .Builder()
                .add("grant_type", "authorization_code")
                .add("code", code)
                .add("redirect_uri", redirectUri)
                .add("client_id", requireNotNull(configuration.clientId) { "A registered client is required." })
                .add("code_verifier", codeVerifier)
                .build(),
        )

    fun refresh(
        configuration: OidcConfiguration,
        refreshToken: String,
    ): AuthTokens =
        tokenRequest(
            configuration.tokenEndpoint,
            FormBody
                .Builder()
                .add("grant_type", "refresh_token")
                .add("refresh_token", refreshToken)
                .add("client_id", requireNotNull(configuration.clientId) { "A registered client is required." })
                .build(),
        )

    fun profile(
        serverUrl: String,
        authorization: String,
    ): UserProfile {
        val root =
            bodyJson(
                Request
                    .Builder()
                    .url("$serverUrl/ocs/v2.php/cloud/user?format=json")
                    .header("Authorization", authorization)
                    .header("OCS-APIREQUEST", "true")
                    .get()
                    .build(),
            ).jsonObject
        val data = root["ocs"]?.jsonObject?.get("data")?.jsonObject ?: error("Missing OCS user data")
        return UserProfile(
            id = data.requiredString("id"),
            displayName = data["display-name"]?.jsonPrimitive?.content ?: data.requiredString("id"),
            email = data["email"]?.jsonPrimitive?.content,
        )
    }

    private fun tokenRequest(
        endpoint: String,
        body: FormBody,
    ): AuthTokens {
        val data =
            bodyJson(
                Request
                    .Builder()
                    .url(endpoint)
                    .post(body)
                    .build(),
            ).jsonObject
        val expiresIn = data["expires_in"]?.jsonPrimitive?.content?.toLongOrNull() ?: 3600L
        return AuthTokens(
            accessToken = data.requiredString("access_token"),
            refreshToken = data["refresh_token"]?.jsonPrimitive?.content,
            expiresAtEpochSeconds = (clock.epochMillis() / 1000) + expiresIn.coerceIn(0, 31536000),
            tokenType = data["token_type"]?.jsonPrimitive?.content ?: "Bearer",
            scope = data["scope"]?.jsonPrimitive?.content,
        )
    }

    private fun bodyJson(request: Request) = json.parseToJsonElement(execute(request).body)

    private fun execute(
        request: Request,
        consumeBody: Boolean = true,
    ): HttpResponse {
        endpoints.endpoint(request.url.toString())
        return client.newCall(request).execute().use { response ->
            val tokenRequest = request.isTokenRequest()
            val body = readResponseBody(request, response, consumeBody, tokenRequest)
            if (!response.isSuccessful) {
                throw response.toHttpException(tokenRequest, body)
            }
            HttpResponse(response.headers, body)
        }
    }

    private fun readResponseBody(
        request: Request,
        response: okhttp3.Response,
        consumeBody: Boolean,
        tokenRequest: Boolean,
    ): String {
        if (!consumeBody) {
            if (!response.isSuccessful) throw TransferHttpException(response.code)
            return ""
        }
        val limit =
            when {
                !response.isSuccessful -> ERROR_METADATA_LIMIT_BYTES
                tokenRequest -> AUTH_METADATA_LIMIT_BYTES
                request.url.encodedPath.endsWith("/.well-known/webfinger") ||
                    request.url.encodedPath.endsWith("/.well-known/openid-configuration") -> SMALL_METADATA_LIMIT_BYTES
                else -> LISTING_METADATA_LIMIT_BYTES
            }
        return response.readBoundedMetadata(limit)
    }

    private fun okhttp3.Response.toHttpException(
        tokenRequest: Boolean,
        body: String,
    ): TransferHttpException {
        val oauthError =
            if (tokenRequest && code in setOf(400, 401)) {
                runCatching {
                    json
                        .parseToJsonElement(body)
                        .jsonObject["error"]
                        ?.jsonPrimitive
                        ?.content
                }.getOrNull()
            } else {
                null
            }
        val failure =
            when (oauthError) {
                "invalid_grant" -> OpenCloudError.AuthenticationRequired
                "invalid_client" -> OpenCloudError.ClientRegistrationRequired
                else -> httpError(code)
            }
        return TransferHttpException(code, error = failure)
    }

    private fun Request.isTokenRequest() =
        (body as? FormBody)?.let { form ->
            (0 until form.size).any { form.name(it) == "grant_type" }
        } == true

    private fun normalizeServerUrl(value: String): String {
        val withScheme = if ("://" in value) value else "https://$value"
        return endpoints.endpoint(withScheme, allowQuery = false).toString().trimEnd('/')
    }

    private fun kotlinx.serialization.json.JsonObject.requiredString(name: String): String =
        get(name)?.jsonPrimitive?.content ?: error("Missing required field: $name")

    private companion object {
        const val OIDC_ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer"
        const val LEGACY_ISSUER_REL = "http://opencloud.eu/ns/oidc/issuer"
    }
}

data class DiscoveryResult(
    val canonicalServerUrl: String,
)

private data class HttpResponse(
    val headers: okhttp3.Headers,
    val body: String,
)
