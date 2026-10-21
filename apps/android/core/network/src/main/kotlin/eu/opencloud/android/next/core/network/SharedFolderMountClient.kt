package eu.opencloud.android.next.core.network

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request

/** Resolves only an exact remote-item identity, never the mount drive's own ID or a guessed DAV URL. */
class SharedFolderMountClient(
    client: OkHttpClient,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
    private val json = Json { ignoreUnknownKeys = true }

    fun remoteDriveId(
        serverUrl: String,
        authorization: String,
        itemId: String,
    ): String? = remoteTarget(serverUrl, authorization, itemId)?.driveId

    fun remoteTarget(
        serverUrl: String,
        authorization: String,
        itemId: String,
    ): SharedMountTarget? {
        if (itemId.isBlank()) invalid()
        val initial =
            endpoints
                .endpoint(serverUrl, allowQuery = false)
                .newBuilder()
                .addPathSegments("graph/v1beta1/me/drives")
                .addQueryParameter("\$filter", "driveType eq mountpoint")
                .build()
        val visited = mutableSetOf<String>()
        val identities = mutableSetOf<String>()
        val matches = mutableSetOf<SharedMountTarget>()
        var remainingBytes = 16 * MAX_PAGE_BYTES
        var next: HttpUrl? = initial
        while (next != null) {
            val url = next
            checkPage(initial, url)
            if (!visited.add(url.toString()) || visited.size > 1000) invalid()
            val (page, bytes) = read(url, authorization)
            remainingBytes -= bytes
            if (remainingBytes < 0) invalid()
            page.value.forEach { mount ->
                if (mount.id.isBlank() || !identities.add(mount.id) || identities.size > 100_000) invalid()
                if (mount.matches(itemId)) {
                    val remote = mount.root?.remoteItem
                    matches += SharedMountTarget(remote?.parentReference?.driveId, remote?.webDavUrl)
                }
            }
            next = page.nextLink?.let { endpoints.endpoint(url.resolve(it)?.toString() ?: invalid()) }
        }
        return matches.singleOrNull()
    }

    private fun checkPage(
        initial: HttpUrl,
        page: HttpUrl,
    ) {
        if (!sameOrigin(initial, page) || initial.encodedPath != page.encodedPath) {
            throw OpenCloudException(OpenCloudError.Trust)
        }
    }

    private fun sameOrigin(
        first: HttpUrl,
        second: HttpUrl,
    ): Boolean = first.scheme == second.scheme && first.host == second.host && first.port == second.port

    private fun ShareMount.matches(itemId: String): Boolean =
        driveType == "mountpoint" && root?.deleted == null && root?.remoteItem?.id == itemId

    private fun read(
        url: HttpUrl,
        authorization: String,
    ): Pair<MountPage, Long> {
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .get()
                .build()
        return client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw TransferHttpException(response.code, parseRetryAfter(response.header("Retry-After")))
            }
            val source = response.body?.source() ?: invalid()
            source.request(MAX_PAGE_BYTES + 1)
            if (source.buffer.size > MAX_PAGE_BYTES) invalid()
            val bytes = source.buffer.size
            try {
                json.decodeFromString<MountPage>(source.readUtf8()) to bytes
            } catch (_: SerializationException) {
                invalid()
            } catch (_: IllegalArgumentException) {
                invalid()
            }
        }
    }

    private fun invalid(): Nothing = throw SharedMetadataException(SharedMetadataStage.MOUNT)

    private companion object {
        const val MAX_PAGE_BYTES = 1024 * 1024L
    }
}

data class SharedMountTarget(
    val driveId: String?,
    val webDavUrl: String?,
)

@Serializable
private data class MountPage(
    val value: List<ShareMount>,
    @SerialName("@odata.nextLink") val nextLink: String? = null,
)

@Serializable
private data class ShareMount(
    val id: String,
    val driveType: String? = null,
    val root: ShareMountRoot? = null,
)

@Serializable
private data class ShareMountRoot(
    val remoteItem: SharedRemoteItem? = null,
    val deleted: JsonObject? = null,
)
