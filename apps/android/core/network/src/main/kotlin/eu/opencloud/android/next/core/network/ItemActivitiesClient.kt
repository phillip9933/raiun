package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.time.Instant

data class ItemActivity(
    val id: String,
    val message: String,
    val recordedTime: String,
)

/** The same item-scoped feed used by the web sidebar. Server messages stay plain text. */
class ItemActivitiesClient(
    client: OkHttpClient,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val http =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

    fun list(
        server: String,
        authorization: String,
        itemId: String,
    ): List<ItemActivity> {
        // IDs enter the server's query language as well as a URL. Never allow query operators.
        require(itemId.matches(Regex("[A-Za-z0-9!$._~-]{1,1024}")))
        val url =
            endpoints
                .endpoint(server, allowQuery = false)
                .newBuilder()
                .addPathSegments("graph/v1beta1/extensions/org.libregraph/activities")
                .addQueryParameter("kql", "itemid:$itemId AND limit:200 AND sort:desc")
                .build()
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .get()
                .build()
        return http.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                throw TransferHttpException(
                    response.code,
                    parseRetryAfter(response.header("Retry-After")),
                )
            }
            val source = response.body?.source() ?: invalid()
            source.request(2 * 1024 * 1024L + 1)
            if (source.buffer.size > 2 * 1024 * 1024L) invalid()
            val envelope = Json.parseToJsonElement(source.readUtf8()) as? JsonObject ?: invalid()
            val rows = envelope["value"] as? JsonArray ?: invalid()
            if (rows.size > 200) invalid()
            val items = rows.map { parse(it as? JsonObject ?: invalid()) }
            if (items.map { it.id }.distinct().size != items.size) invalid()
            items.sortedByDescending { Instant.parse(it.recordedTime) }
        }
    }

    private fun parse(row: JsonObject): ItemActivity {
        val template = row["template"] as? JsonObject ?: invalid()
        val variables = template["variables"] as? JsonObject
        val message = template.text("message").ifBlank { invalid() }
        // One pass prevents a name containing {anotherVariable} from being substituted again.
        val rendered =
            Regex("\\{([^{}]+)\\}").replace(message) { match ->
                val value = variables?.get(match.groupValues[1]) as? JsonObject
                value?.text("displayName")?.ifBlank { value.text("name") }?.takeIf { it.isNotBlank() } ?: match.value
            }
        val time = (row["times"] as? JsonObject)?.text("recordedTime") ?: invalid()
        Instant.parse(time)
        return ItemActivity(row.text("id").ifBlank { invalid() }, rendered, time)
    }

    private fun JsonObject.text(key: String): String = (get(key) as? JsonPrimitive)?.contentOrNull.orEmpty()

    private fun invalid(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)
}
