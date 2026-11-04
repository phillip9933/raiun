package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import eu.opencloud.android.next.core.model.auth.UserProfile
import eu.opencloud.android.next.core.model.auth.WebFingerMetadata
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
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
                    .addQueryParameter("platform", "android")
                    .build()
            val root =
                bodyJson(
                    Request
                        .Builder()
                        .url(endpoint)
                        .get()
                        .build(),
                ) as? JsonObject ?: invalidOidcMetadata()
            val properties =
                when (val value = root["properties"]) {
                    null, JsonNull -> null
                    is JsonObject -> value
                    else -> invalidOidcMetadata()
                }
            val links =
                when (val value = root["links"]) {
                    null, JsonNull -> emptyList()
                    is JsonArray -> value.map { it as? JsonObject ?: invalidOidcMetadata() }
                    else -> invalidOidcMetadata()
                }
            val issuerLink =
                (
                    links.firstOrNull { oidcMetadataString(it["rel"]) == OIDC_ISSUER_REL }
                        ?: links.firstOrNull { oidcMetadataString(it["rel"]) == LEGACY_ISSUER_REL }
                )
            val issuer = issuerLink?.let { oidcMetadataString(it["href"]) }
            WebFingerMetadata(
                issuer = issuer,
                clientId = properties?.get("http://opencloud.eu/ns/oidc/client_id")?.let { oidcMetadataString(it) },
                scopes = parseScopeArray(properties?.get("http://opencloud.eu/ns/oidc/scopes"), allowScopeText = true),
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
            ) as? JsonObject ?: invalidOidcMetadata()
        val scopes =
            webFinger?.scopes ?: parseScopeArray(root["scopes_supported"]).orEmpty()
        if (endpoints.issuer(oidcMetadataString(root["issuer"])) != expectedIssuer) {
            throw OpenCloudException(OpenCloudError.Trust)
        }
        validateOidcFlowMetadata(root)
        return OidcConfiguration(
            issuer = expectedIssuer,
            authorizationEndpoint = endpoints.endpoint(oidcMetadataString(root["authorization_endpoint"])).toString(),
            tokenEndpoint = endpoints.endpoint(oidcMetadataString(root["token_endpoint"])).toString(),
            registrationEndpoint =
                root["registration_endpoint"]
                    ?.let { oidcMetadataString(it) }
                    ?.let { endpoints.endpoint(it).toString() },
            clientId = webFinger?.clientId,
            scopes = scopes.ifEmpty { listOf("openid", "profile") },
            authorizationResponseIssParameterSupported =
                oidcResponseIssuerSupported(root["authorization_response_iss_parameter_supported"]),
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
            ) as? JsonObject ?: invalidOidcMetadata()
        val data = (root["ocs"] as? JsonObject)?.get("data") as? JsonObject ?: invalidOidcMetadata()
        return UserProfile(
            id = data.requiredString("id"),
            displayName = data.optionalProfileString("display-name") ?: data.requiredString("id"),
            email = data.optionalProfileString("email"),
        )
    }

    private fun tokenRequest(
        endpoint: String,
        body: FormBody,
    ): AuthTokens {
        val response =
            execute(
                Request
                    .Builder()
                    .url(endpoint)
                    .post(body)
                    .build(),
            )
        return parseOAuthTokenResponse(response.body, clock.epochMillis() / 1000, json)
    }

    private fun bodyJson(request: Request) =
        try {
            json.parseToJsonElement(execute(request).body)
        } catch (_: kotlinx.serialization.SerializationException) {
            invalidOidcMetadata()
        }

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
                // A status-only/proxy 401 is not evidence that a refresh grant was revoked.
                // Only the explicit invalid_grant branch may trigger destructive session cleanup.
                else -> if (tokenRequest && code == 401) OpenCloudError.HttpFailure(code) else httpError(code)
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
        oidcMetadataString(get(name))

    private fun JsonObject.optionalProfileString(name: String): String? {
        val element = get(name)
        if (element == null || element == JsonNull) return null
        val primitive = element as? kotlinx.serialization.json.JsonPrimitive ?: invalidOidcMetadata()
        if (!primitive.isString) invalidOidcMetadata()
        return primitive.content
    }

    private companion object {
        const val OIDC_ISSUER_REL = "http://openid.net/specs/connect/1.0/issuer"
        const val LEGACY_ISSUER_REL = "http://opencloud.eu/ns/oidc/issuer"
    }
}

private fun parseScopeArray(
    value: JsonElement?,
    allowScopeText: Boolean = false,
): List<String>? {
    if (value == null || value == JsonNull) return null
    val array = value as? JsonArray ?: invalidOidcMetadata()
    return array.flatMap { element ->
        val primitive = element as? kotlinx.serialization.json.JsonPrimitive ?: invalidOidcMetadata()
        if (!primitive.isString) invalidOidcMetadata()
        // OpenCloud WebFinger entries may contain complete scope text; IdP entries are individual tokens.
        val scopes =
            if (allowScopeText) primitive.content.split(' ').filter(String::isNotEmpty) else listOf(primitive.content)
        if (scopes.isEmpty() || scopes.any { !it.isValidOAuthScopeToken() }) invalidOidcMetadata()
        scopes
    }
}

// RFC 6749 section 3.3: preserve individual scope tokens, including commas, without splitting or trimming.
private fun String.isValidOAuthScopeToken(): Boolean =
    isNotEmpty() &&
        all { character ->
            val code = character.code
            code == 0x21 || code in 0x23..0x5b || code in 0x5d..0x7e
        }

private fun invalidOidcMetadata(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

data class DiscoveryResult(
    val canonicalServerUrl: String,
)

private data class HttpResponse(
    val headers: okhttp3.Headers,
    val body: String,
)
