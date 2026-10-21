package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.ServerAppProvider
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/** Only consumed protocol fields are decoded. Unknown fields cannot enable a feature. */
internal class CapabilitiesParser {
    private val json = Json { ignoreUnknownKeys = true }

    fun parse(
        body: String,
        serverUrl: String,
    ): ServerCapabilities {
        val envelope =
            try {
                json.decodeFromString<Envelope>(body)
            } catch (_: SerializationException) {
                throw OpenCloudException(OpenCloudError.Unsupported)
            }
        val meta = envelope.ocs.meta
        if (meta != null && meta.statuscode !in setOf(100, 200)) {
            throw OpenCloudException(OpenCloudError.Unsupported)
        }
        val data = envelope.ocs.data
        val caps = data.capabilities
        val sharing = caps.sharing
        val public = sharing?.public
        return ServerCapabilities(
            version = data.version?.string,
            sharingEnabled = sharing?.apiEnabled ?: sharing?.api.enabled(),
            publicSharingEnabled = public?.enabled ?: public?.apiEnabled ?: false,
            spacesEnabled = caps.spaces?.enabled == true,
            tusSupported = caps.files?.tus?.let { it.version == "1.0.0" && it.resumable == "1.0.0" } == true,
            remoteSearchUrl =
                if (caps.dav?.reports?.contains("search-files") == true) {
                    "${serverUrl.trimEnd('/')}/remote.php/dav/spaces/"
                } else {
                    null
                },
            trashSupported = caps.dav?.trashbin.enabled(allowVersion = true),
            publicLinkPasswordSupported = public?.password != null,
            publicLinkPasswordEnforced = public?.password?.enforced == true,
            publicLinkExpirationSupported = public?.expiration?.enabled == true,
            publicLinkExpirationEnforced = public?.expiration?.enforced == true,
            publicLinkExpirationDays = public?.expiration?.days?.takeIf { it > 0 },
            appProviders =
                caps.files
                    ?.appProviders
                    .orEmpty()
                    .filter { it.enabled && !it.appsUrl.isNullOrBlank() }
                    .map {
                        ServerAppProvider(
                            requireNotNull(it.appsUrl),
                            it.openWebUrl?.takeIf(String::isNotBlank),
                            it.openUrl?.takeIf(String::isNotBlank),
                        )
                    },
        )
    }
}

// Legacy scalar/version forms are restricted to the exact fields that used them.
private fun JsonElement?.enabled(allowVersion: Boolean = false): Boolean =
    when (this) {
        is JsonPrimitive ->
            booleanOrNull ?: (content == "1" || (allowVersion && VERSION.matches(content)))
        is JsonObject -> {
            val explicit = get("enabled") ?: get("api_enabled")
            if (explicit != null) {
                explicit.enabled()
            } else if (allowVersion) {
                get("version").enabled(true)
            } else {
                false
            }
        }
        else -> false
    }

private val VERSION = Regex("[1-9][0-9]*\\.[0-9]+(?:\\.[0-9]+)?")

@Serializable
private data class Envelope(
    val ocs: OcsCapabilities,
)

@Serializable
private data class OcsCapabilities(
    val data: CapabilityData,
    val meta: OcsMeta? = null,
)

@Serializable
private data class OcsMeta(
    val statuscode: Int,
)

@Serializable
private data class CapabilityData(
    val capabilities: CapabilitiesDto,
    val version: VersionDto? = null,
)

@Serializable
private data class VersionDto(
    val string: String? = null,
)

@Serializable
private data class CapabilitiesDto(
    val files: FilesDto? = null,
    val dav: DavDto? = null,
    val spaces: SpacesDto? = null,
    @SerialName("files_sharing") val sharing: SharingDto? = null,
)

@Serializable
private data class FilesDto(
    @SerialName("tus_support") val tus: TusDto? = null,
    @SerialName("app_providers") val appProviders: List<AppProviderDto>? = null,
)

@Serializable
private data class AppProviderDto(
    val enabled: Boolean = false,
    @SerialName("apps_url") val appsUrl: String? = null,
    @SerialName("open_web_url") val openWebUrl: String? = null,
    @SerialName("open_url") val openUrl: String? = null,
)

@Serializable
private data class TusDto(
    val version: String? = null,
    val resumable: String? = null,
)

@Serializable
private data class DavDto(
    val reports: List<String> = emptyList(),
    val trashbin: JsonElement? = null,
)

@Serializable
private data class SpacesDto(
    val enabled: Boolean = false,
)

@Serializable
private data class SharingDto(
    @SerialName("api_enabled") val apiEnabled: Boolean? = null,
    val api: JsonElement? = null,
    val public: PublicDto? = null,
)

@Serializable
private data class PublicDto(
    val enabled: Boolean? = null,
    @SerialName("api_enabled") val apiEnabled: Boolean? = null,
    val password: PasswordDto? = null,
    @SerialName("expire_date") val expiration: ExpirationDto? = null,
)

@Serializable
private data class PasswordDto(
    val enforced: Boolean = false,
)

@Serializable
private data class ExpirationDto(
    val enabled: Boolean = false,
    val enforced: Boolean = false,
    val days: Int? = null,
)
