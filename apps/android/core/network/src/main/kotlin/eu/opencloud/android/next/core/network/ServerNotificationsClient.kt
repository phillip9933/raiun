package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

data class ServerNotification(
    val id: String,
    val subject: String,
    val message: String,
    val dateTime: String,
    val isShare: Boolean,
)

/** OCS notification inbox; server text is plain text, never executable HTML or an automatic URL. */
class ServerNotificationsClient(
    client: OkHttpClient,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

    fun list(
        server: String,
        authorization: String,
    ): List<ServerNotification> {
        val request = base(server, authorization).get().build()
        val data = execute(request, allowEmpty = true) ?: JsonNull
        // OpenCloud userlog serializes its nil notification slice as JSON null when the inbox is empty.
        if (data == JsonNull) return emptyList()
        val rows = data as? JsonArray ?: invalid()
        if (rows.size > 10000) invalid()
        val result = rows.map { parse(it as? JsonObject ?: invalid()) }
        if (result.map { it.id }.distinct().size != result.size) invalid()
        return result.sortedByDescending { it.dateTime }
    }

    fun markRead(
        server: String,
        authorization: String,
        ids: List<String>,
    ) {
        require(ids.isNotEmpty() && ids.size <= 10000 && ids.all { it.isNotBlank() })
        val payload = buildJsonObject { put("ids", JsonArray(ids.distinct().map(::JsonPrimitive))) }
        execute(
            base(server, authorization)
                .delete(payload.toString().toRequestBody("application/json".toMediaType()))
                .build(),
            allowEmpty = true,
        )
    }

    private fun base(
        server: String,
        authorization: String,
    ): Request.Builder =
        Request
            .Builder()
            .url(
                endpoints
                    .endpoint(server, allowQuery = false)
                    .newBuilder()
                    .addPathSegments("ocs/v2.php/apps/notifications/api/v1/notifications")
                    .build(),
            ).header("Authorization", authorization)
            .header("OCS-APIRequest", "true")
            .header("Accept", "application/json")

    private fun execute(
        request: Request,
        allowEmpty: Boolean,
    ): kotlinx.serialization.json.JsonElement? =
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw TransferHttpException(
                    response.code,
                    parseRetryAfter(response.header("Retry-After")),
                )
            }
            val source = response.body?.source() ?: return@use if (allowEmpty) null else invalid()
            source.request(2 * 1024 * 1024L + 1)
            if (source.buffer.size > 2 * 1024 * 1024L) invalid()
            val body = source.readUtf8()
            if (body.isBlank() && allowEmpty) return@use null
            val envelope = Json.parseToJsonElement(body) as? JsonObject ?: invalid()
            val ocs = envelope["ocs"] as? JsonObject ?: invalid()
            val meta = ocs["meta"] as? JsonObject ?: invalid()
            val status = (meta["statuscode"] as? JsonPrimitive)?.intOrNull ?: invalid()
            if (status !in setOf(100, 200)) throw OpenCloudException(OpenCloudError.InvalidResponse)
            if (!ocs.containsKey("data")) invalid()
            ocs["data"]
        }

    private fun parse(row: JsonObject): ServerNotification {
        val id = row.text("notification_id").ifBlank { invalid() }
        val plain = row.text("message")
        val rich = row.text("messageRich")
        val parameters = row["messageRichParameters"] as? JsonObject
        var message = rich.ifBlank { plain }
        if (parameters != null) {
            mapOf("user" to "displayname", "resource" to "name", "space" to "name", "virus" to "name")
                .forEach { (key, label) ->
                    val value = (parameters[key] as? JsonObject)?.text(label)
                    if (!value.isNullOrBlank()) message = message.replace("{" + key + "}", value)
                }
        }
        if (message.contains(Regex("\\{[a-zA-Z]+\\}")) && plain.isNotBlank()) message = plain
        return ServerNotification(
            id,
            row.text("subject"),
            message,
            row.text("datetime"),
            row.text("object_type") == "share",
        )
    }

    private fun JsonObject.text(key: String): String = (get(key) as? JsonPrimitive)?.contentOrNull.orEmpty()

    private fun invalid(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)
}
