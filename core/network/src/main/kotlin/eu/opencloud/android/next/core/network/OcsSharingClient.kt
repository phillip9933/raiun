package eu.opencloud.android.next.core.network

import android.util.Log
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.time.LocalDate
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.util.UUID

enum class OcsShareType(
    val value: Int,
) {
    USER(0),
    GROUP(1),
    PUBLIC_LINK(3),
}

@Suppress("LongParameterList")
class RemoteShare(
    val id: String,
    val type: OcsShareType,
    val path: String,
    val resourceId: String?,
    val shareWith: String?,
    val displayName: String?,
    val additionalInfo: String?,
    val permissions: Int,
    val sharedAtEpochSeconds: Long,
    val expiresAtEpochMillis: Long?,
    val label: String?,
    val isFolder: Boolean,
    val publicUrl: String?,
)

data class ShareRecipient(
    val type: OcsShareType,
    val shareWith: String,
    val label: String,
    val additionalInfo: String?,
    val exact: Boolean,
)

data class CreateShareRequest(
    val path: String,
    val type: OcsShareType,
    val shareWith: String? = null,
    val permissions: Int = 1,
    val label: String? = null,
    val password: String? = null,
    val expirationDate: LocalDate? = null,
    val resourceId: String? = null,
)

data class UpdateShareRequest(
    val permissions: Int? = null,
    val label: String? = null,
    val password: String? = null,
    val expirationDate: LocalDate? = null,
    val clearExpiration: Boolean = false,
)

class OcsSharingClient(
    client: OkHttpClient,
    private val json: Json = Json { ignoreUnknownKeys = true },
    private val onPolicyUncertain: () -> Unit = {},
) {
    private val client =
        client
            .newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .build()
            .withMetadataDeadline()

    fun listShares(
        serverUrl: String,
        authorization: String,
        sharedWithMe: Boolean = false,
        path: String? = null,
        resourceId: String? = null,
    ): List<RemoteShare> {
        val url =
            sharesUrl(serverUrl)
                .newBuilder()
                .apply {
                    addQueryParameter("format", "json")
                    if (sharedWithMe) addQueryParameter("shared_with_me", "true")
                    resourceId?.let { addQueryParameter("space", it) }
                    path?.takeIf { resourceId == null }?.let {
                        addQueryParameter("path", it)
                        addQueryParameter("reshares", "true")
                        addQueryParameter("subfiles", "false")
                    }
                }.build()
        return execute(
            Request
                .Builder()
                .url(url)
                .ocsHeaders(authorization)
                .get()
                .build(),
        ).ocsData()
            .jsonArray
            .mapNotNull(::parseShare)
    }

    fun searchRecipients(
        serverUrl: String,
        authorization: String,
        query: String,
        page: Int = 1,
        perPage: Int = 50,
    ): List<ShareRecipient> {
        val url =
            serverUrl
                .toHttpUrl()
                .newBuilder()
                .addPathSegments("ocs/v2.php/apps/files_sharing/api/v1/sharees")
                .addQueryParameter("format", "json")
                .addQueryParameter("itemType", "file")
                .addQueryParameter("search", query)
                .addQueryParameter("page", page.toString())
                .addQueryParameter("perPage", perPage.toString())
                .build()
        val data =
            execute(
                Request
                    .Builder()
                    .url(url)
                    .ocsHeaders(authorization)
                    .get()
                    .build(),
            ).ocsData().jsonObject
        return buildList {
            addRecipients(data["exact"] as? JsonObject, exact = true)
            addRecipients(data, exact = false)
        }.distinctBy { "${it.type}:${it.shareWith}" }
    }

    fun createShare(
        serverUrl: String,
        authorization: String,
        value: CreateShareRequest,
    ): RemoteShare {
        val body =
            FormBody
                .Builder()
                .apply { if (value.resourceId != null) add("space", value.resourceId) else add("path", value.path) }
                .add("shareType", value.type.value.toString())
                .apply { value.shareWith?.let { add("shareWith", it) } }
                .add("permissions", value.permissions.toString())
                .apply {
                    value.label?.takeIf(String::isNotBlank)?.let { add("name", it) }
                    value.password?.takeIf(String::isNotBlank)?.let { add("password", it) }
                    value.expirationDate?.let { add("expireDate", it.toString()) }
                }.build()
        return requireNotNull(
            parseShare(
                execute(
                    Request
                        .Builder()
                        .url(
                            sharesUrl(serverUrl).newBuilder().addQueryParameter("format", "json").build(),
                        ).ocsHeaders(authorization)
                        .post(body)
                        .build(),
                ).ocsData(),
            ),
        ) { "The server returned an invalid share." }
    }

    fun updateShare(
        serverUrl: String,
        authorization: String,
        shareId: String,
        value: UpdateShareRequest,
    ): RemoteShare {
        val body =
            FormBody
                .Builder()
                .apply {
                    value.permissions?.let { add("permissions", it.toString()) }
                    value.label?.let { add("name", it) }
                    value.password?.let { add("password", it) }
                    if (value.clearExpiration) {
                        add(
                            "expireDate",
                            "",
                        )
                    } else {
                        value.expirationDate?.let { add("expireDate", it.toString()) }
                    }
                }.build()
        val url =
            sharesUrl(serverUrl)
                .newBuilder()
                .addPathSegment(shareId)
                .addQueryParameter("format", "json")
                .build()
        return requireNotNull(
            parseShare(
                execute(
                    Request
                        .Builder()
                        .url(url)
                        .ocsHeaders(authorization)
                        .put(body)
                        .build(),
                ).ocsData(),
            ),
        )
    }

    fun revokeShare(
        serverUrl: String,
        authorization: String,
        shareId: String,
    ) {
        val url =
            sharesUrl(serverUrl)
                .newBuilder()
                .addPathSegment(shareId)
                .addQueryParameter("format", "json")
                .build()
        execute(
            Request
                .Builder()
                .url(url)
                .ocsHeaders(authorization)
                .delete()
                .build(),
        )
    }

    private fun Request.Builder.ocsHeaders(authorization: String) =
        header("Authorization", authorization)
            .header("OCS-APIREQUEST", "true")
            .header("Accept", "application/json")
            .header("X-Requested-With", "XMLHttpRequest")
            .header("X-Request-ID", UUID.randomUUID().toString())

    private fun execute(request: Request): JsonElement =
        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                val body = response.readBoundedMetadata(ERROR_METADATA_LIMIT_BYTES)
                if (response.code in setOf(403, 404, 405)) onPolicyUncertain()
                runCatching {
                    Log.e(
                        LOG_TAG,
                        "${request.method} failed with HTTP ${response.code}",
                    )
                }
                throw TransferHttpException(
                    response.code,
                    error = publicLinkPasswordError(response.code, body),
                )
            }
            val body = response.readBoundedMetadata(LISTING_METADATA_LIMIT_BYTES)
            val root = json.parseToJsonElement(body)
            val meta = root.jsonObject["ocs"]?.jsonObject?.get("meta") as? JsonObject
            val ocsStatus = meta?.get("statuscode")?.jsonPrimitive?.intOrNull
            if (ocsStatus != null && ocsStatus !in SUCCESSFUL_OCS_STATUS_CODES) {
                runCatching {
                    Log.e(
                        LOG_TAG,
                        "${request.method} failed with OCS status $ocsStatus",
                    )
                }
                val message = meta["message"]?.jsonPrimitive?.content?.take(512)
                throw TransferHttpException(
                    ocsStatus,
                    error = publicLinkPasswordError(ocsStatus, message.orEmpty()),
                )
            }
            root
        }

    private fun JsonElement.ocsData(): JsonElement =
        jsonObject["ocs"]?.jsonObject?.get("data") ?: error("Missing OCS response data")

    private fun parseShare(element: JsonElement): RemoteShare? {
        val value = element.jsonObject
        val id = value.string("id")
        val type =
            value.string("share_type")?.toIntOrNull()?.let { code ->
                OcsShareType.entries.firstOrNull { it.value == code }
            }
        if (id == null || type == null) return null
        return RemoteShare(
            id = id,
            type = type,
            path = value.string("path").orEmpty(),
            resourceId = value.string("item_source") ?: value.string("file_source"),
            shareWith = value.string("share_with"),
            displayName = value.string("share_with_displayname"),
            additionalInfo = value.string("share_with_additional_info"),
            permissions = value.string("permissions")?.toIntOrNull() ?: 1,
            sharedAtEpochSeconds = value.string("stime")?.toLongOrNull() ?: 0,
            expiresAtEpochMillis = value.string("expiration")?.toExpirationMillis(),
            label = value.string("name"),
            isFolder = value.string("item_type") == "folder",
            publicUrl = value.string("url"),
        )
    }

    private fun MutableList<ShareRecipient>.addRecipients(
        container: JsonObject?,
        exact: Boolean,
    ) {
        listOf("users" to OcsShareType.USER, "groups" to OcsShareType.GROUP).forEach { (key, type) ->
            (container?.get(key) as? kotlinx.serialization.json.JsonArray)?.forEach { element ->
                val item = element.jsonObject
                val value = item["value"]?.jsonObject ?: return@forEach
                val shareWith = value.string("shareWith") ?: return@forEach
                add(
                    ShareRecipient(
                        type,
                        shareWith,
                        item.string("label") ?: shareWith,
                        value.string("shareWithAdditionalInfo"),
                        exact,
                    ),
                )
            }
        }
    }

    private companion object {
        const val LOG_TAG = "OpenCloudSync"
        val SUCCESSFUL_OCS_STATUS_CODES = setOf(100, 200)
    }
}

private fun sharesUrl(serverUrl: String) =
    serverUrl
        .toHttpUrl()
        .newBuilder()
        .addPathSegments("ocs/v2.php/apps/files_sharing/api/v1/shares")
        .build()

private fun JsonObject.string(key: String) = get(key)?.jsonPrimitive?.content

private fun String.toExpirationMillis(): Long? =
    runCatching { OffsetDateTime.parse(this).toInstant().toEpochMilli() }.getOrElse {
        runCatching {
            LocalDate
                .parse(this)
                .atStartOfDay()
                .toInstant(ZoneOffset.UTC)
                .toEpochMilli()
        }.getOrNull()
    }

private fun publicLinkPasswordError(
    statusCode: Int,
    responseText: String,
): OpenCloudError =
    if (statusCode == 400 && missingSharePassword(responseText)) {
        OpenCloudError.PublicLinkPasswordRequired
    } else if (statusCode == 400) {
        val minimums = passwordMinimums(responseText)
        val reason = if (minimums.isEmpty()) shareRejection(responseText) else ShareRejection.PASSWORD_POLICY
        OpenCloudError.ShareRejected(reason, minimums)
    } else {
        httpError(statusCode)
    }

private fun missingSharePassword(text: String): Boolean =
    listOf("missing required password", "password is required", "password required").any { text.contains(it, true) }

/** Keep only known character classes and bounded numeric requirements, never the response text. */
private fun passwordMinimums(text: String): Map<PasswordCharacterClass, Int> =
    PasswordCharacterClass.entries
        .mapNotNull { kind ->
            val pattern = Regex("at least ([0-9]{1,5}) ${kind.label} are required", RegexOption.IGNORE_CASE)
            val count =
                pattern
                    .find(text)
                    ?.groupValues
                    ?.get(1)
                    ?.toIntOrNull()
                    ?.takeIf { it in 1..10000 }
            count?.let { kind to it }
        }.toMap()

private fun shareRejection(responseText: String): ShareRejection =
    when {
        responseText.contains("password", true) -> ShareRejection.PASSWORD_POLICY
        responseText.contains("permission", true) ||
            responseText.contains("role", true) ||
            responseText.contains("resharing", true) -> ShareRejection.PERMISSIONS
        responseText.contains("space reference", true) -> ShareRejection.RESOURCE_REFERENCE
        responseText.contains("share space root", true) -> ShareRejection.SPACE_ROOT
        responseText.contains(
            "datetime",
            true,
        ) ||
            responseText.contains("expiration", true) -> ShareRejection.EXPIRATION
        responseText.contains(
            "parse form",
            true,
        ) ||
            responseText.contains("shareType must", true) -> ShareRejection.REQUEST_FORMAT
        else -> ShareRejection.UNKNOWN
    }
