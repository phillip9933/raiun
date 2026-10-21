package eu.opencloud.android.next.core.network

import android.util.Log
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.UUID

class LibreGraphSpacesClient(
    client: OkHttpClient,
    private val json: Json = Json { ignoreUnknownKeys = true },
    private val initiatorId: String = CLIENT_INITIATOR_ID,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
            .withMetadataDeadline()

    fun listSpaces(
        serverUrl: String,
        authorization: String,
    ): List<RemoteSpace> = snapshot(serverUrl, authorization).spaces

    /** Creates a project space through LibreGraph; persistence is confirmed by a subsequent snapshot. */
    fun createProjectSpace(
        serverUrl: String,
        authorization: String,
        name: String,
    ): String = createSpace(serverUrl, authorization, name, contentType = null)

    /** Creates a project drive carrying Web's vault marker and no default template. */
    fun createVaultSpace(
        serverUrl: String,
        authorization: String,
        name: String,
    ): String = createSpace(serverUrl, authorization, name, VAULT_CONTENT_TYPE)

    private fun createSpace(
        serverUrl: String,
        authorization: String,
        name: String,
        contentType: String?,
    ): String {
        require(name.isNotBlank())
        val url =
            endpoints
                .endpoint(drivesUrl(serverUrl, includeMe = false))
                .newBuilder()
                .apply { if (contentType != null) addQueryParameter("template", "none") }
                .build()
        val body =
            buildJsonObject {
                put("name", name.trim())
                contentType?.let { put("@libre.graph.contentType", it) }
            }.toString()
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .header("Initiator-ID", initiatorId)
                .header("X-Requested-With", "XMLHttpRequest")
                .header("X-Request-ID", UUID.randomUUID().toString())
                .post(body.toRequestBody(JSON_MEDIA_TYPE))
                .build()
        return client.newCall(request).execute().use { response ->
            if (response.code != 201) {
                runCatching { Log.e(LOG_TAG, "POST failed with HTTP ${response.code}") }
                throw TransferHttpException(response.code)
            }
            val responseBody = response.readBoundedMetadata(SMALL_METADATA_LIMIT_BYTES)
            val drive = json.parseToJsonElement(responseBody).jsonObject
            val id =
                drive.string("id")?.takeIf { it.isNotBlank() }
                    ?: throw OpenCloudException(OpenCloudError.Unsupported)
            id
        }
    }

    fun updateProjectSpace(
        serverUrl: String,
        authorization: String,
        driveId: String,
        update: ProjectSpaceUpdate,
    ): RemoteSpace {
        val name = update.name
        val description = update.description
        val quotaBytes = update.quotaBytes
        require(driveId.isNotBlank())
        require(name != null || description != null || quotaBytes != null)
        require(name == null || name.isNotBlank())
        require(quotaBytes == null || quotaBytes >= 0)
        val requestBody =
            buildJsonObject {
                name?.let { put("name", it.trim()) }
                description?.let { put("description", it) }
                quotaBytes?.let { put("quota", buildJsonObject { put("total", it) }) }
            }.toString()
        val responseBody =
            managementRequest(
                serverUrl,
                authorization,
                DriveManagementRequest(
                    driveId = driveId,
                    method = "PATCH",
                    body = requestBody,
                    contentType = "application/json",
                    expectedCode = 200,
                ),
            )
        return parseDriveResponse(responseBody)
    }

    /** Disables a space while preserving its content, as defined by OpenCloud's Spaces API. */
    fun disableProjectSpace(
        serverUrl: String,
        authorization: String,
        driveId: String,
    ) = managementRequest(serverUrl, authorization, DriveManagementRequest(driveId, "DELETE", expectedCode = 204))

    fun enableProjectSpace(
        serverUrl: String,
        authorization: String,
        driveId: String,
    ) = managementRequest(
        serverUrl,
        authorization,
        DriveManagementRequest(
            driveId,
            method = "PATCH",
            body = "{}",
            contentType = "text/plain",
            headers = mapOf("Restore" to "T"),
            expectedCode = 200,
        ),
    )

    /** Permanently deletes a previously disabled space. */
    fun permanentlyDeleteProjectSpace(
        serverUrl: String,
        authorization: String,
        driveId: String,
    ) = managementRequest(
        serverUrl,
        authorization,
        DriveManagementRequest(
            driveId,
            method = "DELETE",
            headers = mapOf("Purge" to "T"),
            expectedCode = 204,
        ),
    )

    private fun managementRequest(
        serverUrl: String,
        authorization: String,
        management: DriveManagementRequest,
    ): String {
        require(management.driveId.isNotBlank())
        val url =
            serverUrl
                .toHttpUrl()
                .newBuilder()
                .addPathSegments("graph/v1.0/drives")
                .addPathSegment(management.driveId)
                .build()
                .toString()
                .let(endpoints::endpoint)
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .header("Initiator-ID", initiatorId)
                .header("X-Requested-With", "XMLHttpRequest")
                .header("X-Request-ID", UUID.randomUUID().toString())
                .apply {
                    management.headers.forEach { (name, value) -> header(name, value) }
                    this.method(
                        management.method,
                        management.body?.toRequestBody((management.contentType ?: "text/plain").toMediaType()),
                    )
                }.build()
        return executeManagement(request, management.expectedCode)
    }

    // Network causes can include private host details; expose only the typed public failure category.
    @Suppress("SwallowedException")
    private fun executeManagement(
        request: Request,
        expectedCode: Int,
    ): String =
        try {
            client.newCall(request).execute().use { response ->
                if (response.code != expectedCode) throw TransferHttpException(response.code)
                response.readBoundedMetadata(AUTH_METADATA_LIMIT_BYTES)
            }
        } catch (failure: java.io.IOException) {
            throw OpenCloudException(failure.toOpenCloudError())
        }

    private fun parseDriveResponse(body: String): RemoteSpace {
        val element =
            try {
                json.parseToJsonElement(body)
            } catch (_: kotlinx.serialization.SerializationException) {
                throw OpenCloudException(OpenCloudError.InvalidResponse)
            }
        return (element as? JsonObject)?.toRemoteSpace()
            ?: throw OpenCloudException(OpenCloudError.InvalidResponse)
    }

    /** Exclusions are authoritative only when the entire paginated response succeeds. */
    fun snapshot(
        serverUrl: String,
        authorization: String,
        includeAllSpaces: Boolean = false,
        includeVaultDetails: Boolean = false,
    ): RemoteSpacesSnapshot {
        val spaces = mutableListOf<RemoteSpace>()
        val excluded = mutableSetOf<String>()
        val vaultSpaces = mutableListOf<RemoteSpace>()
        val initial = endpoints.endpoint(drivesUrl(serverUrl, includeMe = !includeAllSpaces))
        val visited = mutableSetOf<String>()
        val ids = mutableSetOf<String>()
        var nextUrl: String? = initial.toString()
        while (nextUrl != null) {
            val url = endpoints.endpoint(nextUrl)
            if (url.scheme != initial.scheme || url.host != initial.host || url.port != initial.port) {
                throw OpenCloudException(OpenCloudError.Trust)
            }
            if (!visited.add(url.toString()) || visited.size > 1000) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            val page = execute(url.toString(), authorization, includeVaultDetails)
            requireCompletePage(page.spaces.map { it.id } + page.excludedVaultIds, ids)
            spaces += page.spaces
            excluded += page.excludedVaultIds
            vaultSpaces += page.vaultSpaces
            nextUrl =
                page.nextUrl?.let {
                    resolvePage(url, it)
                }
        }
        return RemoteSpacesSnapshot(spaces.toList(), excluded.toSet(), vaultSpaces.toList())
    }

    private fun execute(
        url: String,
        authorization: String,
        includeVaultDetails: Boolean,
    ): SpacesPage {
        val request =
            Request
                .Builder()
                .url(url)
                .header("Authorization", authorization)
                .header("Accept", "application/json")
                .header("Initiator-ID", initiatorId)
                .header("X-Requested-With", "XMLHttpRequest")
                .header("X-Request-ID", UUID.randomUUID().toString())
                .get()
                .build()
        return client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                runCatching { Log.e(LOG_TAG, "GET failed with HTTP ${response.code}") }
                throw TransferHttpException(response.code)
            }
            val body = response.readBoundedMetadata(LISTING_METADATA_LIMIT_BYTES)
            val payload = json.parseToJsonElement(body).jsonObject
            val records =
                (payload["value"] ?: throw OpenCloudException(OpenCloudError.Unsupported))
                    .jsonArray
                    .map { it.jsonObject }
            val (vaults, visible) = records.partition { it.string("@libre.graph.contentType") == VAULT_CONTENT_TYPE }
            SpacesPage(
                spaces = visible.map { it.toRemoteSpace() },
                excludedVaultIds = vaults.map { it.vaultId() },
                vaultSpaces = if (includeVaultDetails) vaults.map { it.toRemoteSpace() } else emptyList(),
                nextUrl = payload.string("@odata.nextLink"),
            )
        }
    }

    private companion object {
        const val LOG_TAG = "OpenCloudSync"
        const val VAULT_CONTENT_TYPE = "application/vnd.opencloud.vault"
        val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
        val CLIENT_INITIATOR_ID = UUID.randomUUID().toString()
    }
}

private fun resolvePage(
    base: okhttp3.HttpUrl,
    link: String,
): String = base.resolve(link)?.toString() ?: throw OpenCloudException(OpenCloudError.Trust)

private fun requireCompletePage(
    spaceIds: List<String>,
    ids: MutableSet<String>,
) {
    if (spaceIds.any { it.isBlank() || !ids.add(it) } || ids.size > 100_000) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun JsonObject.vaultId(): String =
    string("id")?.takeIf { it.isNotBlank() } ?: throw OpenCloudException(OpenCloudError.Unsupported)

data class RemoteSpacesSnapshot(
    val spaces: List<RemoteSpace>,
    val excludedVaultIds: Set<String>,
    val vaultSpaces: List<RemoteSpace> = emptyList(),
)

data class ProjectSpaceUpdate(
    val name: String? = null,
    val description: String? = null,
    val quotaBytes: Long? = null,
)

private data class DriveManagementRequest(
    val driveId: String,
    val method: String,
    val body: String? = null,
    val contentType: String? = null,
    val headers: Map<String, String> = emptyMap(),
    val expectedCode: Int,
)

data class RemoteSpace(
    val id: String,
    val name: String,
    val type: String,
    val description: String?,
    val driveAlias: String?,
    val webUrl: String?,
    val ownerId: String?,
    val ownerName: String?,
    val lastModifiedDateTime: String?,
    val rootId: String,
    val rootWebDavUrl: String,
    val rootETag: String?,
    val quotaTotalBytes: Long?,
    val quotaUsedBytes: Long?,
    val quotaRemainingBytes: Long?,
    val quotaState: String?,
    val disabled: Boolean,
    val deleted: Boolean,
)

private data class SpacesPage(
    val spaces: List<RemoteSpace>,
    val excludedVaultIds: List<String>,
    val vaultSpaces: List<RemoteSpace>,
    val nextUrl: String?,
)

private fun JsonObject.toRemoteSpace(): RemoteSpace {
    val root = requiredObject("root")
    val deletedState = root["deleted"]?.jsonObject?.string("state")
    val owner = get("owner")?.jsonObject?.get("user")?.jsonObject
    val quota = get("quota")?.jsonObject
    val type = string("driveType") ?: "project"
    return RemoteSpace(
        id = requiredString("id"),
        name = requiredString("name"),
        type = type,
        description = string("description"),
        driveAlias = string("driveAlias"),
        webUrl = string("webUrl"),
        ownerId = owner?.string("id"),
        ownerName = owner?.string("displayName"),
        lastModifiedDateTime = string("lastModifiedDateTime"),
        rootId = root.requiredString("id"),
        rootWebDavUrl = root.requiredString("webDavUrl"),
        rootETag = root.string("eTag"),
        quotaTotalBytes = quota?.long("total"),
        quotaUsedBytes = quota?.long("used"),
        quotaRemainingBytes = quota?.long("remaining"),
        quotaState = quota?.string("state"),
        disabled = deletedState == "trashed",
        // Permanently deleted spaces are absent from Graph listings; a trashed root is a disabled space.
        deleted = false,
    )
}

private fun drivesUrl(
    serverUrl: String,
    includeMe: Boolean = true,
): String =
    serverUrl
        .toHttpUrl()
        .newBuilder()
        .apply {
            addPathSegments(if (includeMe) "graph/v1.0/me/drives" else "graph/v1.0/drives")
        }.build()
        .toString()

private fun JsonObject.requiredString(name: String): String =
    string(name) ?: throw OpenCloudException(OpenCloudError.InvalidResponse)

private fun JsonObject.requiredObject(name: String): JsonObject =
    get(name)?.jsonObject ?: throw OpenCloudException(OpenCloudError.InvalidResponse)

private fun JsonObject.string(name: String): String? = get(name)?.jsonPrimitive?.content

private fun JsonObject.long(name: String): Long? = string(name)?.toLongOrNull()
