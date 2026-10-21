package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

data class SpaceMember(
    val id: String,
    val name: String,
    val roles: List<String>,
    val group: Boolean,
)

data class SpaceMemberRole(
    val id: String,
    val name: String,
)

data class SpaceMembers(
    val members: List<SpaceMember>,
    val roles: List<SpaceMemberRole>,
)

/** Space membership uses root permissions, never the caller's Personal drive or OCS file-share endpoint. */
class SpaceMembersClient(
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
        auth: String,
        drive: String,
    ): SpaceMembers {
        val data = requireNotNull(request(server, auth, drive, listOf("permissions"), "GET", null))
        require(data["@odata.nextLink"] == null) { "The member listing is incomplete." }
        val rows = data["value"] as? JsonArray ?: invalid()
        val members =
            rows.mapNotNull { element ->
                val row = element as? JsonObject ?: invalid()
                if (row["link"] != null) return@mapNotNull null
                val recipient = row["grantedToV2"] as? JsonObject ?: return@mapNotNull null
                val user = recipient["user"] as? JsonObject
                val group = recipient["group"] as? JsonObject
                val identity = user ?: group ?: return@mapNotNull null
                SpaceMember(
                    row.text("id").ifBlank { invalid() },
                    identity.text("displayName").ifBlank { identity.text("id") },
                    (row["roles"] as? JsonArray).orEmpty().map { (it as? JsonPrimitive)?.contentOrNull ?: invalid() },
                    group != null,
                )
            }
        val roles =
            (data["@libre.graph.permissions.roles.allowedValues"] as? JsonArray).orEmpty().map { element ->
                val role = element as? JsonObject ?: invalid()
                SpaceMemberRole(role.text("id").ifBlank { invalid() }, role.text("displayName"))
            }
        return SpaceMembers(members, roles)
    }

    fun add(
        server: String,
        auth: String,
        drive: String,
        recipient: ShareRecipient,
        role: String,
    ) {
        require(recipient.type in setOf(OcsShareType.USER, OcsShareType.GROUP))
        require(recipient.shareWith.isNotBlank() && role.isNotBlank())
        val payload =
            buildJsonObject {
                put("roles", JsonArray(listOf(JsonPrimitive(role))))
                put(
                    "recipients",
                    JsonArray(
                        listOf(
                            buildJsonObject {
                                put("objectId", recipient.shareWith)
                                put(
                                    "@libre.graph.recipient.type",
                                    if (recipient.type ==
                                        OcsShareType.GROUP
                                    ) {
                                        "group"
                                    } else {
                                        "user"
                                    },
                                )
                            },
                        ),
                    ),
                )
            }
        request(server, auth, drive, listOf("invite"), "POST", payload)
    }

    fun update(
        server: String,
        auth: String,
        drive: String,
        permission: String,
        role: String,
    ) {
        require(permission.isNotBlank() && permission !in setOf(".", "..") && role.isNotBlank())
        request(
            server,
            auth,
            drive,
            listOf("permissions", permission),
            "PATCH",
            buildJsonObject { put("roles", JsonArray(listOf(JsonPrimitive(role)))) },
        )
    }

    fun remove(
        server: String,
        auth: String,
        drive: String,
        permission: String,
    ) {
        require(permission.isNotBlank() && permission !in setOf(".", ".."))
        request(server, auth, drive, listOf("permissions", permission), "DELETE", null)
    }

    @Suppress("LongParameterList") // Explicit authenticated endpoint, resource, method and payload.
    private fun request(
        server: String,
        auth: String,
        drive: String,
        path: List<String>,
        method: String,
        payload: JsonObject?,
    ): JsonObject? {
        require(drive.isNotBlank() && drive !in setOf(".", ".."))
        val url =
            endpoints
                .endpoint(server, allowQuery = false)
                .newBuilder()
                .addPathSegments("graph/v1beta1/drives")
                .addPathSegment(drive)
                .addPathSegment("root")
        path.forEach(url::addPathSegment)
        val request =
            Request
                .Builder()
                .url(url.build())
                .header("Authorization", auth)
                .header("Accept", "application/json")
                .method(method, payload?.toString()?.toRequestBody("application/json".toMediaType()))
                .build()
        return http.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw TransferHttpException(response.code)
            val body = response.body ?: return@use null
            val source = body.source()
            source.request(2 * 1024 * 1024L + 1)
            if (source.buffer.size > 2 * 1024 * 1024L) invalid()
            val text = source.readUtf8()
            if (text.isBlank()) null else Json.parseToJsonElement(text) as? JsonObject ?: invalid()
        }
    }

    private fun JsonObject.text(key: String) = (get(key) as? JsonPrimitive)?.contentOrNull.orEmpty()

    private fun invalid(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)
}
