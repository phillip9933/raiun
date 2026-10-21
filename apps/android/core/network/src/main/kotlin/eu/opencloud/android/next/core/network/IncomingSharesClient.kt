package eu.opencloud.android.next.core.network

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request

/** Read-only discovery. No guessed DAV paths, mounting requests, or partial snapshots. */
class IncomingSharesClient(
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

    fun list(
        serverUrl: String,
        authorization: String,
    ): List<IncomingSharedItem> {
        val initial =
            endpoints
                .endpoint(serverUrl, allowQuery = false)
                .newBuilder()
                .addPathSegments("graph/v1beta1/me/drive/sharedWithMe")
                .build()
        val items = mutableListOf<IncomingSharedItem>()
        val visited = mutableSetOf<String>()
        val identities = mutableSetOf<String>()
        var remainingBytes = MAX_INVENTORY_BYTES
        var next: HttpUrl? = initial
        while (next != null) {
            val url = next
            requirePageOrigin(initial, url)
            if (!visited.add(url.toString()) || visited.size > 1000) invalid()
            val (page, bytes) = read(url, authorization)
            remainingBytes -= bytes
            if (remainingBytes < 0) invalid()
            page.value.forEach { item ->
                validate(item, initial)
                if (!identities.add(item.id) || identities.size > 100_000) invalid()
                items.add(item)
            }
            next = page.nextLink?.let { endpoints.endpoint(url.resolve(it)?.toString() ?: invalid()) }
        }
        return items
    }

    private fun read(
        url: HttpUrl,
        authorization: String,
    ): Pair<SharedItemsPage, Long> {
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
            val body = response.body ?: invalid()
            val source = body.source()
            source.request(MAX_PAGE_BYTES + 1)
            if (source.buffer.size > MAX_PAGE_BYTES) invalid()
            val bytes = source.buffer.size
            try {
                json.decodeFromString<SharedItemsPage>(source.readUtf8()) to bytes
            } catch (_: SerializationException) {
                invalid()
            } catch (_: IllegalArgumentException) {
                invalid()
            }
        }
    }

    private fun validate(
        item: IncomingSharedItem,
        initial: HttpUrl,
    ) {
        val remote = item.remoteItem
        val name = item.name?.takeIf(String::isNotBlank) ?: remote.name
        if (item.id.isBlank() || remote.id.isBlank() || name.isNullOrBlank()) invalid()
        val folder = item.folder ?: remote.folder
        val file = item.file ?: remote.file
        if ((folder == null) == (file == null)) invalid()
        remote.webDavUrl?.let {
            val dav = endpoints.endpoint(it, allowQuery = false)
            if (!sameOrigin(initial, dav)) throw OpenCloudException(OpenCloudError.Trust)
        }
    }

    private fun requirePageOrigin(
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

    private fun invalid(): Nothing = throw SharedMetadataException(SharedMetadataStage.INVENTORY)

    private companion object {
        const val MAX_PAGE_BYTES = 4 * 1024 * 1024L
        const val MAX_INVENTORY_BYTES = 16 * 1024 * 1024L
    }
}

@Serializable
private data class SharedItemsPage(
    val value: List<IncomingSharedItem>,
    @SerialName("@odata.nextLink") val nextLink: String? = null,
)
