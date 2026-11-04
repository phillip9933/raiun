package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.put
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.time.Instant
import java.time.format.DateTimeParseException

/** Opaque Graph resource IDs, never DAV paths, public URLs or invitation tokens. */
data class GraphShareTarget(
    val driveId: String,
    val itemId: String,
) {
    init {
        requireGuestSegment(driveId)
        requireGuestSegment(itemId)
    }
}

data class GuestRole(
    val id: String,
    val name: String,
)

data class GuestPermission(
    val id: String,
    val email: String,
    val roles: List<String>,
    val expirationDateTime: String?,
)

data class GuestPermissions(
    val guests: List<GuestPermission>,
    val roles: List<GuestRole>,
)

/**
 * OpenCloud 9 file/folder guest permissions. Every mutation refreshes item-scoped metadata first.
 * Ordinary user/group/link permissions stay in their existing clients; no invitation URL is retained.
 */
class GuestPermissionsClient(
    client: OkHttpClient,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
    private val beforeRequest: () -> Unit = {},
) {
    private val http =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .build()
            .withMetadataDeadline()

    fun list(
        server: String,
        auth: String,
        target: GraphShareTarget,
    ): GuestPermissions {
        val data = request(server, auth, target, listOf("permissions"), "GET") ?: invalidGuestMetadata()
        if (data["@odata.nextLink"] != null) invalidGuestMetadata()
        val roles = parseRoles(data)
        // OpenCloud 9 omits value for an empty permission collection. Only list accepts
        // this shape, after validating item-scoped role metadata; mutation results stay strict.
        val rows = if ("value" in data) collection(data) else emptyList()
        val guests = rows.mapNotNull { parseGuest(it, roles) }
        if (guests.map { it.id }.distinct().size != guests.size) invalidGuestMetadata()
        return GuestPermissions(guests, roles)
    }

    @Suppress("LongParameterList") // Explicit account, resource and invitation fields.
    fun invite(
        server: String,
        auth: String,
        target: GraphShareTarget,
        email: String,
        roleId: String,
        expirationDateTime: String? = null,
    ): GuestPermission {
        require(validGuestEmail(email))
        requireGuestExpiration(expirationDateTime)
        val roles = list(server, auth, target).roles
        requireAllowedGuestRole(roleId, roles)
        val payload =
            buildJsonObject {
                put("roles", JsonArray(listOf(JsonPrimitive(roleId))))
                put("recipients", JsonArray(listOf(buildJsonObject { put("email", email) })))
                expirationDateTime?.let { put("expirationDateTime", it) }
            }
        val data = request(server, auth, target, listOf("invite"), "POST", payload) ?: invalidGuestMetadata()
        val rows = collection(data)
        if (rows.size != 1) invalidGuestMetadata()
        return parseGuest(rows.single(), roles)?.also {
            if (it.roles != listOf(roleId)) invalidGuestMetadata()
        } ?: invalidGuestMetadata()
    }

    @Suppress("LongParameterList") // Explicit account, resource, permission and requested settings.
    fun update(
        server: String,
        auth: String,
        target: GraphShareTarget,
        permissionId: String,
        roleId: String,
        expirationDateTime: String? = null,
    ): GuestPermission {
        requireGuestSegment(permissionId)
        requireGuestExpiration(expirationDateTime)
        val current = list(server, auth, target)
        require(current.guests.any { it.id == permissionId })
        requireAllowedGuestRole(roleId, current.roles)
        val payload =
            buildJsonObject {
                put("roles", JsonArray(listOf(JsonPrimitive(roleId))))
                // Explicit null requests removal of expiry; omission would retain the old value.
                put("expirationDateTime", expirationDateTime?.let(::JsonPrimitive) ?: JsonNull)
            }
        val data =
            request(server, auth, target, listOf("permissions", permissionId), "PATCH", payload)
                ?: invalidGuestMetadata()
        return parseGuest(data, current.roles)?.also {
            if (it.id != permissionId || it.roles != listOf(roleId)) invalidGuestMetadata()
        } ?: invalidGuestMetadata()
    }

    fun remove(
        server: String,
        auth: String,
        target: GraphShareTarget,
        permissionId: String,
    ) {
        requireGuestSegment(permissionId)
        require(list(server, auth, target).guests.any { it.id == permissionId })
        request(server, auth, target, listOf("permissions", permissionId), "DELETE")
    }

    @Suppress("LongParameterList", "SwallowedException") // Safe failures must not retain response or transport data.
    // One bounded request with explicit origin, target, verb and body.
    private fun request(
        server: String,
        auth: String,
        target: GraphShareTarget,
        path: List<String>,
        method: String,
        payload: JsonObject? = null,
    ): JsonObject? {
        require(auth.isNotBlank() && auth.none(Char::isISOControl))
        val url =
            endpoints
                .endpoint(server, allowQuery = false)
                .newBuilder()
                .addPathSegments("graph/v1beta1/drives")
                .addPathSegment(target.driveId)
                .addPathSegment("items")
                .addPathSegment(target.itemId)
        path.forEach(url::addPathSegment)
        val request =
            Request
                .Builder()
                .url(url.build())
                .header("Authorization", auth)
                .header("Accept", "application/json")
                .method(method, payload?.toString()?.toRequestBody("application/json".toMediaType()))
                .build()
        beforeRequest()
        try {
            return http.newCall(request).execute().use { response ->
                val expected = if (method == "DELETE") 204 else 200
                if (response.code != expected) {
                    throw OpenCloudException(httpError(response.code, parseRetryAfter(response.header("Retry-After"))))
                }
                if (method == "DELETE") return@use null
                val body = response.readBoundedMetadata(GUEST_METADATA_LIMIT_BYTES)
                try {
                    Json.parseToJsonElement(body) as? JsonObject ?: invalidGuestMetadata()
                } catch (_: IllegalArgumentException) {
                    invalidGuestMetadata()
                }
            }
        } catch (error: IOException) {
            throw OpenCloudException(error.toOpenCloudError())
        }
    }
}

private const val GUEST_METADATA_LIMIT_BYTES = 2 * 1024 * 1024L
private val GUEST_ROLE_ID = Regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
private val GUEST_EMAIL = Regex("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")

private fun requireGuestSegment(value: String) {
    require(value.isNotBlank() && value.length <= 4096 && value !in setOf(".", "..") && value.none(Char::isISOControl))
}

private fun validGuestEmail(value: String): Boolean =
    value.length <= 254 &&
        value.substringBefore('@').length <= 64 &&
        GUEST_EMAIL.matches(value) &&
        !value.startsWith('.') &&
        !value.substringBefore('@').endsWith('.') &&
        !value.contains("..")

private fun validGuestExpiration(value: String?): Boolean =
    value == null ||
        (
            value.length <= 64 &&
                try {
                    Instant.parse(value)
                    true
                } catch (_: DateTimeParseException) {
                    false
                }
        )

private fun requireGuestExpiration(value: String?) = require(validGuestExpiration(value))

private fun requireAllowedGuestRole(
    id: String,
    roles: List<GuestRole>,
) = require(roles.any { it.id == id })

private fun JsonObject.guestText(key: String): String? =
    (get(key) as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

private fun collection(data: JsonObject): List<JsonObject> {
    val rows = data["value"] as? JsonArray ?: invalidGuestMetadata()
    if (rows.size > 1000) invalidGuestMetadata()
    return rows.map { it as? JsonObject ?: invalidGuestMetadata() }
}

private fun parseRoles(data: JsonObject): List<GuestRole> {
    val rows = data["@libre.graph.permissions.roles.allowedValues"] as? JsonArray ?: invalidGuestMetadata()
    if (rows.size > 64) invalidGuestMetadata()
    val roles =
        rows.map { value ->
            val role = value as? JsonObject ?: invalidGuestMetadata()
            val id = role.guestText("id")?.takeIf(GUEST_ROLE_ID::matches) ?: invalidGuestMetadata()
            val name =
                role.guestText("displayName")?.takeIf {
                    it.isNotBlank() &&
                        it.length <= 256 &&
                        it.none(Char::isISOControl)
                }
                    ?: invalidGuestMetadata()
            GuestRole(id, name)
        }
    if (roles.map { it.id }.distinct().size != roles.size) invalidGuestMetadata()
    return roles
}

@Suppress("ReturnCount") // Each early return filters a different non-guest permission kind.
private fun parseGuest(row: JsonObject, allowedRoles: List<GuestRole>): GuestPermission? {
    if (row["link"] != null) return null
    val recipient = row["grantedToV2"] as? JsonObject ?: return null
    if (recipient["group"] != null) return null
    val user = recipient["user"] as? JsonObject ?: return null
    if (user.guestText("@libre.graph.userType") != "Guest") return null
    val id = row.guestText("id") ?: invalidGuestMetadata()
    try {
        requireGuestSegment(id)
    } catch (_: IllegalArgumentException) {
        invalidGuestMetadata()
    }
    val email = user.guestText("id")?.takeIf(::validGuestEmail) ?: invalidGuestMetadata()
    return GuestPermission(id, email, parseGuestRoles(row, allowedRoles), parseGuestExpiry(row))
}

private fun parseGuestRoles(
    row: JsonObject,
    allowedRoles: List<GuestRole>,
): List<String> {
    val roles =
        (row["roles"] as? JsonArray)?.map {
            (it as? JsonPrimitive)?.takeIf { role -> role.isString }?.contentOrNull ?: invalidGuestMetadata()
        } ?: invalidGuestMetadata()
    if (roles.isEmpty() || roles.size > 64 || roles.distinct().size != roles.size) invalidGuestMetadata()
    if (roles.any { role -> allowedRoles.none { it.id == role } }) invalidGuestMetadata()
    return roles
}

private fun parseGuestExpiry(row: JsonObject): String? {
    val expiryElement = row["expirationDateTime"]
    val expiry =
        if (expiryElement == null || expiryElement == JsonNull) {
            null
        } else {
            row.guestText("expirationDateTime")
                ?: invalidGuestMetadata()
        }
    if (!validGuestExpiration(expiry)) invalidGuestMetadata()
    return expiry
}

private fun invalidGuestMetadata(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)
