package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.ServerAppProvider
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

data class ServerWebApp(
    val name: String,
    val mimeType: String,
    val extension: String?,
    val isDefault: Boolean,
)

/** Never persist launch URLs or forward account credentials to an editor. */
class ServerWebAppClient(
    client: OkHttpClient,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .callTimeout(30, TimeUnit.SECONDS)
            .build()
    private val json = Json { ignoreUnknownKeys = true }

    fun list(
        server: String,
        provider: ServerAppProvider,
        authorization: String,
    ): List<ServerWebApp> {
        val request = request(endpoint(server, provider.appsUrl), authorization).get().build()
        val registry = decode<WebAppRegistry>(execute(request))
        if (registry.mimeTypes.size > 1000) invalid()
        val result =
            registry.mimeTypes.flatMap { type ->
                if (!MIME.matches(type.mimeType) || type.providers.size > 100) invalid()
                type.providers.map { app ->
                    if (!validLabel(app.name)) invalid()
                    ServerWebApp(app.name, type.mimeType, type.extension, app.name == type.defaultApplication)
                }
            }
        if (result.size > 5000 || result.distinctBy { it.mimeType to it.name }.size != result.size) invalid()
        return result
    }

    /** Re-fetches the registry so a stale or invented application cannot be submitted. */
    fun openInWeb(
        server: String,
        provider: ServerAppProvider,
        authorization: String,
        fileId: String,
        app: ServerWebApp,
    ): String {
        val open = provider.openWebUrl ?: throw OpenCloudException(OpenCloudError.Unsupported)
        val target = endpoint(server, open)
        if (!validLabel(fileId) || app !in list(server, provider, authorization)) invalid()
        val form =
            FormBody
                .Builder()
                .add("file_id", fileId)
                .add("app_name", app.name)
                .build()
        val launch = decode<WebAppLaunch>(execute(request(target, authorization).post(form).build()))
        // open_web_url returns the server web UI. Cross-origin embedded-editor contracts are separate.
        return endpoint(server, launch.uri, browserLink = true).toString()
    }

    /** The authenticated server delegates a transient editor session, possibly on another HTTPS origin. */
    fun prepareEmbedded(
        server: String,
        provider: ServerAppProvider,
        authorization: String,
        selection: EmbeddedWebAppRequest,
    ): EmbeddedWebAppSession {
        val open = provider.openUrl ?: throw OpenCloudException(OpenCloudError.Unsupported)
        val target = endpoint(server, open)
        if (!validLabel(selection.fileId) || selection.app !in list(server, provider, authorization)) invalid()
        val url =
            target
                .newBuilder()
                .setQueryParameter("file_id", selection.fileId)
                .setQueryParameter("app_name", selection.app.name)
                .setQueryParameter("view_mode", selection.mode.wireValue)
                .build()
        val response = execute(request(url, authorization).post(ByteArray(0).toRequestBody()).build())
        return decode<EmbeddedWebAppResponse>(response).session(endpoints)
    }

    private fun endpoint(
        server: String,
        value: String,
        browserLink: Boolean = false,
    ): HttpUrl {
        val origin = endpoints.endpoint(server.trimEnd('/') + "/", allowQuery = false)
        if (value.isBlank() || value.length > 8192 || value.any { it.isISOControl() }) trust()
        val resolved = origin.resolve(value) ?: trust()
        val checked = if (browserLink) resolved.newBuilder().fragment(null).build() else resolved
        val url = endpoints.endpoint(checked.toString())
        if (origin.scheme != url.scheme || origin.host != url.host || origin.port != url.port) trust()
        return resolved
    }

    private fun request(
        url: HttpUrl,
        authorization: String,
    ) = Request
        .Builder()
        .url(url)
        .header("Authorization", authorization)
        .header("Accept", "application/json")

    private fun execute(request: Request): String =
        client.newCall(request).execute().use { response ->
            if (response.code != 200) {
                throw TransferHttpException(response.code, parseRetryAfter(response.header("Retry-After")))
            }
            val source = response.body?.source() ?: invalid()
            source.request(MAX_BYTES + 1)
            if (source.buffer.size > MAX_BYTES) invalid()
            source.readUtf8()
        }

    private inline fun <reified T> decode(body: String): T =
        try {
            json.decodeFromString<T>(body)
        } catch (_: SerializationException) {
            invalid()
        } catch (_: IllegalArgumentException) {
            invalid()
        }

    private fun validLabel(value: String) =
        value.isNotBlank() && value.length <= 1024 && value.none { it.isISOControl() }

    private fun invalid(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

    private fun trust(): Nothing = throw OpenCloudException(OpenCloudError.Trust)

    private companion object {
        const val MAX_BYTES = 2 * 1024 * 1024L
        val MIME = Regex("[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+")
    }
}

@Serializable
private data class WebAppRegistry(
    @SerialName("mime-types") val mimeTypes: List<WebAppMime>,
)

@Serializable
private data class WebAppMime(
    @SerialName("mime_type") val mimeType: String,
    @SerialName("app_providers") val providers: List<WebAppEntry>,
    @SerialName("ext") val extension: String? = null,
    @SerialName("default_application") val defaultApplication: String? = null,
)

@Serializable
private data class WebAppEntry(
    val name: String,
)

@Serializable
private data class WebAppLaunch(
    val uri: String,
)
