package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.crypto.VaultContentIntegrityException
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException

/** Preserve stream I/O and permission failures; only a rejected ciphertext becomes an integrity error. */
internal inline fun <T> authenticatedVaultContent(block: () -> T): T =
    try {
        block()
    } catch (_: VaultContentIntegrityException) {
        throw OpenCloudException(OpenCloudError.DownloadIntegrity)
    }
