package eu.opencloud.android.next.core.network

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/** Updates the caller's share-jail entry, never the owner's folder or permissions. */
class IncomingShareVisibilityClient(
    client: OkHttpClient,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

    fun setHidden(
        serverUrl: String,
        authorization: String,
        share: IncomingSharedItem,
        hidden: Boolean,
    ) {
        val drive = share.parentReference?.driveId
        require(!drive.isNullOrBlank() && drive !in setOf(".", ".."))
        require(share.id.isNotBlank() && share.id !in setOf(".", ".."))
        val url =
            endpoints
                .endpoint(serverUrl, allowQuery = false)
                .newBuilder()
                .addPathSegments("graph/v1beta1/drives")
                .addPathSegment(drive)
                .addPathSegment("items")
                .addPathSegment(share.id)
                .build()
        val body = "{\"@UI.Hidden\":" + hidden + "}"
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .patch(body.toRequestBody("application/json".toMediaType()))
                .build()
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw TransferHttpException(response.code, parseRetryAfter(response.header("Retry-After")))
            }
        }
    }
}
