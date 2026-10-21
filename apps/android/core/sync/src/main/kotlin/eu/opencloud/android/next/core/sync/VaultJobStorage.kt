package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

/** Scope this to filesystem calls, never to a source stream or HTTP callback. */
internal fun <T> vaultJobWrite(block: () -> T): T =
    try {
        block()
    } catch (error: IOException) {
        throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed).apply { initCause(error) }
    }

internal fun <T> vaultJobRead(block: () -> T): T =
    try {
        block()
    } catch (error: FileNotFoundException) {
        throw OpenCloudException(OpenCloudError.SourceUnavailable).apply { initCause(error) }
    } catch (error: IOException) {
        throw OpenCloudException(OpenCloudError.DownloadIntegrity).apply { initCause(error) }
    } catch (error: IllegalStateException) {
        throw OpenCloudException(OpenCloudError.DownloadIntegrity).apply { initCause(error) }
    }

internal fun vaultJobRequireWrite(condition: Boolean) {
    if (!condition) throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
}

/** Deletes symlinks themselves; a corrupted private job must never redirect cleanup outside its root. */
internal fun deleteVaultJobTree(file: File): Boolean =
    when {
        java.nio.file.Files
            .isSymbolicLink(file.toPath()) -> file.delete()
        file.isDirectory && file.listFiles().orEmpty().any { !deleteVaultJobTree(it) } -> false
        else -> !file.exists() || file.delete()
    }
