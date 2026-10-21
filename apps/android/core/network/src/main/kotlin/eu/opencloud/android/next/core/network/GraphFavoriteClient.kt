package eu.opencloud.android.next.core.network

import android.util.Log
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.UUID

class GraphFavoriteClient(
    client: OkHttpClient,
    private val initiatorId: String = CLIENT_INITIATOR_ID,
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()

    fun setFavorite(
        serverUrl: String,
        itemId: String,
        authorization: String,
        favorite: Boolean,
    ) {
        val requestBuilder =
            Request
                .Builder()
                .url(if (favorite) followUrl(serverUrl, itemId) else unfollowUrl(serverUrl, itemId))
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .header("Initiator-ID", initiatorId)
                .header("X-Requested-With", "XMLHttpRequest")
                .header("X-Request-ID", UUID.randomUUID().toString())
        val request =
            if (favorite) {
                requestBuilder.post(EMPTY_BODY).build()
            } else {
                requestBuilder.delete().build()
            }

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                runCatching {
                    Log.e(
                        LOG_TAG,
                        "${request.method} failed with HTTP ${response.code}",
                    )
                }
                throw TransferHttpException(response.code)
            }
        }
    }

    private companion object {
        const val LOG_TAG = "OpenCloudSync"
        val CLIENT_INITIATOR_ID = UUID.randomUUID().toString()
        val EMPTY_BODY = ByteArray(0).toRequestBody(null)
    }
}

private fun followUrl(
    serverUrl: String,
    itemId: String,
): String =
    serverUrl
        .toHttpUrl()
        .newBuilder()
        .addPathSegments("graph/v1.0/me/drive/items")
        .addPathSegment(itemId)
        .addPathSegment("follow")
        .build()
        .toString()

private fun unfollowUrl(
    serverUrl: String,
    itemId: String,
): String =
    serverUrl
        .toHttpUrl()
        .newBuilder()
        .addPathSegments("graph/v1.0/me/drive/following")
        .addPathSegment(itemId)
        .build()
        .toString()
