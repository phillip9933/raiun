package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import org.json.JSONObject
import java.io.File

/** Display/offline presentation never changes an encrypted root's actual security scope. */
internal fun VaultLocation.matchesOfflineScope(other: VaultLocation): Boolean {
    if (!isVaultRoot || !other.isVaultRoot) return false

    fun VaultLocation.scope() = copy(title = "", isDisabled = false, offlineOnly = false, offlineUnavailable = false)
    return scope() == other.scope()
}

internal fun boundOfflineCatalog(
    directory: File,
    live: VaultLocation,
    durability: OfflineDurability,
): VaultLocation {
    val bytes = readOfflineMetadata(File(directory, "root.json"), 64 * 1024, durability)
    val cached = decodeVaultRootDescriptor(JSONObject(VaultOfflineIndexCodec.text(bytes)))
    if (!cached.matchesOfflineScope(live)) throw OpenCloudException(OpenCloudError.OfflineSnapshotChanged)
    return cached
}
