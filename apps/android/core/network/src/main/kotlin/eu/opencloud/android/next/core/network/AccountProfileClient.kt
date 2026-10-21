package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

data class ServerAccountProfile(
    val username: String,
    val displayName: String,
    val email: String?,
    val groups: List<String>,
    val usedBytes: Long?,
    val totalBytes: Long?,
)

/** Same authenticated Graph endpoints as the web account page. Never follow a credential-bearing redirect. */
class AccountProfileClient(
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

    fun details(
        server: String,
        authorization: String,
    ): ServerAccountProfile {
        val request =
            request(server, authorization, "me")
                .url(
                    endpoints
                        .endpoint(server, allowQuery = false)
                        .newBuilder()
                        .addPathSegments("graph/v1.0/me")
                        .addQueryParameter("\$expand", "memberOf")
                        .build(),
                ).build()
        val root = Json.parseToJsonElement(requireNotNull(execute(request, MAX_METADATA)).decodeToString()).jsonObject
        val quota = (root["drive"] as? JsonObject)?.get("quota") as? JsonObject
        return ServerAccountProfile(
            username = root.string("onPremisesSamAccountName") ?: root.string("id").orEmpty(),
            displayName = root.string("displayName").orEmpty(),
            email = root.string("mail"),
            groups =
                (root["memberOf"] as? JsonArray).orEmpty().mapNotNull {
                    (it as? JsonObject)?.string(
                        "displayName",
                    )
                },
            usedBytes =
                quota
                    ?.get("used")
                    ?.jsonPrimitive
                    ?.longOrNull
                    ?.takeIf { it >= 0 },
            totalBytes =
                quota
                    ?.get("total")
                    ?.jsonPrimitive
                    ?.longOrNull
                    ?.takeIf { it > 0 },
        )
    }

    fun photo(
        server: String,
        authorization: String,
    ): ByteArray? =
        execute(request(server, authorization, "me/photo/\$value").build(), MAX_PHOTO, missingAllowed = true)

    fun uploadPhoto(
        server: String,
        authorization: String,
        bytes: ByteArray,
        mime: String,
    ) {
        require(bytes.size in 1..MAX_PHOTO && mime == "image/jpeg")
        execute(
            request(server, authorization, "me/photo/\$value")
                .patch(bytes.toRequestBody(mime.toMediaType()))
                .build(),
            MAX_METADATA,
        )
    }

    fun removePhoto(
        server: String,
        authorization: String,
    ) {
        execute(
            request(server, authorization, "me/photo/\$value").delete().build(),
            MAX_METADATA,
            missingAllowed = true,
        )
    }

    private fun request(
        server: String,
        authorization: String,
        path: String,
    ): Request.Builder =
        Request
            .Builder()
            .url(
                endpoints
                    .endpoint(server, allowQuery = false)
                    .newBuilder()
                    .addPathSegments("graph/v1.0/$path")
                    .build(),
            ).header("Authorization", authorization)

    private fun execute(
        request: Request,
        limit: Int,
        missingAllowed: Boolean = false,
    ): ByteArray? =
        client.newCall(request).execute().use { response ->
            if (missingAllowed && response.code == 404) return@use null
            if (!response.isSuccessful) throw TransferHttpException(response.code, error = httpError(response.code))
            val source = response.body?.source() ?: return@use byteArrayOf()
            source.request(limit.toLong() + 1)
            if (source.buffer.size > limit) throw OpenCloudException(OpenCloudError.InvalidResponse)
            source.readByteArray()
        }

    private fun JsonObject.string(key: String) = get(key)?.jsonPrimitive?.contentOrNull

    companion object {
        const val MAX_PHOTO = 10 * 1024 * 1024
        private const val MAX_METADATA = 1024 * 1024
    }
}
