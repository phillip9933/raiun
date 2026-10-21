package eu.opencloud.android.next.core.network

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.security.MessageDigest

data class DavObject(
    val folder: Boolean,
    val size: Long,
    val eTag: String?,
    val checksums: Map<String, String> = emptyMap(),
)

/** Conditional DAV requests; the caller journals phases and verifies content before source removal. */
class DavOperationClient(
    client: OkHttpClient,
) {
    private val client =
        client
            .newBuilder()
            .dispatcher(okhttp3.Dispatcher())
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()

    fun cancelRequests() = client.dispatcher.cancelAll()

    fun stat(
        url: String,
        authorization: String,
    ): DavObject? {
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Depth", "0")
                .method("PROPFIND", PROPERTIES.toRequestBody("application/xml".toMediaType()))
                .build()
        return client.newCall(request).execute().use { response ->
            if (response.code == 404) return@use null
            if (response.code != 207) throw TransferHttpException(response.code)
            val source = requireNotNull(response.body).source()
            if (source.request(MAX_PROPERTIES + 1)) invalid()
            val xml = source.readUtf8()
            if (xml.contains("<!DOCTYPE", true) || xml.contains("<!ENTITY", true)) invalid()
            parseDavObject(xml, url)
        }
    }

    fun mutate(
        source: String,
        destination: String,
        move: Boolean,
        eTag: String,
        authorization: String,
    ) {
        val from = source.toHttpUrl()
        val to = destination.toHttpUrl()
        val credentialsPresent = to.username.isNotEmpty() || to.password.isNotEmpty()
        if (!sameOrigin(from, to) || from == to || credentialsPresent) invalid()
        val version = DownloadExpectation(0, eTag).strongETag ?: invalid()
        val request =
            Request
                .Builder()
                .url(from)
                .header("Authorization", authorization)
                .header("If-Match", version)
                .header("Destination", to.toString())
                .header("Overwrite", "F")
                .header("Depth", "infinity")
                .method(if (move) "MOVE" else "COPY", ByteArray(0).toRequestBody())
                .build()
        val status = client.newCall(request).execute().use { it.code }
        if (status == 412 && stat(source, authorization)?.eTag == version && stat(destination, authorization) != null) {
            throw OpenCloudException(OpenCloudError.Conflict)
        }
        if (status !in setOf(201, 204)) throw TransferHttpException(status)
    }

    fun fingerprint(
        url: String,
        authorization: String,
        checkActive: () -> Unit,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val pending = java.util.ArrayDeque<Pair<String, String>>()
        pending.add(url to "")
        var count = 0
        while (pending.isNotEmpty()) {
            checkActive()
            checkTraversalLimit(++count <= 100_000)
            val (currentUrl, relative) = pending.removeLast()
            checkTraversalLimit(relative.count { it == '/' } <= 256)
            val metadata = stat(currentUrl, authorization) ?: invalid()
            digest.update(relative.toByteArray())
            digest.update(0.toByte())
            digest.update(if (metadata.folder) 1.toByte() else 2.toByte())
            if (metadata.folder) {
                val children =
                    RemoteDiscoveryClient(
                        client,
                    ).folder(currentUrl, "", authorization).sortedByDescending { it.name }
                children.forEach { child ->
                    checkTraversalLimit(pending.size < 100_000)
                    pending.add(
                        currentUrl
                            .toHttpUrl()
                            .newBuilder()
                            .addPathSegment(child.name)
                            .build()
                            .toString() to
                            "$relative/${child.name}",
                    )
                }
            } else {
                digest.update(metadata.size.toString().toByteArray())
                digest.update(0.toByte())
                digest.update(fileFingerprint(currentUrl, metadata, authorization, checkActive))
            }
        }
        return java.util.Base64
            .getEncoder()
            .encodeToString(digest.digest())
    }

    /** Prefer a server-provided cryptographic checksum; old journal fingerprints retain their byte-hash format. */
    fun verificationFingerprint(
        url: String,
        authorization: String,
        checkActive: () -> Unit,
    ): String {
        checkActive()
        val metadata = stat(url, authorization) ?: invalid()
        val algorithm = CHECKSUM_ALGORITHMS.firstOrNull { it in metadata.checksums }
        if (!metadata.folder &&
            algorithm != null &&
            DownloadExpectation(metadata.size, metadata.eTag).strongETag != null
        ) {
            return "checksum-v1:$algorithm:${metadata.size}:${metadata.checksums.getValue(algorithm)}"
        }
        return fingerprint(url, authorization, checkActive)
    }

    fun matchesFingerprint(
        url: String,
        expected: String,
        authorization: String,
        checkActive: () -> Unit,
    ): Boolean {
        if (!expected.startsWith("checksum-v1:")) return fingerprint(url, authorization, checkActive) == expected
        checkActive()
        val parts = expected.split(':')
        if (parts.size != 4 || parts[1] !in CHECKSUM_ALGORITHMS) invalid()
        val metadata = stat(url, authorization)
        return if (metadata == null || metadata.folder || metadata.size != parts[2].toLongOrNull()) {
            false
        } else {
            val actual =
                metadata.checksums[parts[1]] ?: fileFingerprint(url, metadata, authorization, checkActive, parts[1])
                    .joinToString("") { "%02x".format(it.toInt() and 0xff) }
            actual == parts[3]
        }
    }

    fun deleteVerifiedSource(
        url: String,
        eTag: String,
        authorization: String,
    ) {
        WebDavFeatureClient(client).delete(url, authorization, eTag)
    }

    private fun fileFingerprint(
        currentUrl: String,
        metadata: DavObject,
        authorization: String,
        checkActive: () -> Unit,
        algorithm: String = "SHA-256",
    ): ByteArray {
        val version = DownloadExpectation(metadata.size, metadata.eTag).strongETag ?: invalid()
        val request =
            Request
                .Builder()
                .url(currentUrl)
                .header("Authorization", authorization)
                .header("If-Match", version)
                .header("Accept-Encoding", "identity")
                .get()
                .build()
        val content = MessageDigest.getInstance(algorithm)
        client.newCall(request).execute().use { response ->
            if (response.code != 200) throw TransferHttpException(response.code)
            DownloadExpectation(metadata.size, version).validate(response, 0)
            var total = 0L
            val buffer = ByteArray(64 * 1024)
            val input = requireNotNull(response.body).byteStream()
            while (true) {
                checkActive()
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0 || read > metadata.size - total) invalid()
                total += read
                content.update(buffer, 0, read)
            }
            if (total != metadata.size) invalid()
        }
        return content.digest()
    }

    private fun sameOrigin(
        a: HttpUrl,
        b: HttpUrl,
    ) = a.scheme == b.scheme && a.host == b.host && a.port == b.port

    private fun invalid(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)

    private fun checkTraversalLimit(allowed: Boolean) {
        if (!allowed) throw OpenCloudException(OpenCloudError.Unsupported)
    }

    private companion object {
        const val MAX_PROPERTIES = 64L * 1024
        const val PROPERTIES =
            "<d:propfind xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\"><d:prop>" +
                "<d:resourcetype/><d:getcontentlength/><d:getetag/><oc:checksums/></d:prop></d:propfind>"
        val CHECKSUM_ALGORITHMS = listOf("SHA-256", "SHA-1", "MD5")
    }
}
