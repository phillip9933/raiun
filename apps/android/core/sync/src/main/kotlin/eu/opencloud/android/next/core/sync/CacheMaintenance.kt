package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.AtomicFile
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.model.cacheIdentity
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.nio.file.Files
import java.util.Base64

/** Incremental private-cache sweep. Never follow links or delete a currently referenced resource/source. */
internal suspend fun maintainPrivateCache(
    context: Context,
    store: FileBrowserStore,
    cutoff: Long,
) {
    val cursor = context.getSharedPreferences("cache-maintenance", Context.MODE_PRIVATE)
    val roots =
        listOf(
            File(context.filesDir, "resources-v2"),
            File(context.filesDir, "resources"),
            File(context.noBackupFilesDir, "upload-sources"),
            File(context.noBackupFilesDir, "incoming-shares"),
            File(context.cacheDir, "transfers"),
        )
    roots.forEach { root ->
        if (!root.isDirectory || Files.isSymbolicLink(root.toPath())) return@forEach
        val offset = cursor.getInt(root.name, 0).coerceAtLeast(0)
        val safeCutoff =
            if (root.name == "incoming-shares") {
                minOf(
                    cutoff,
                    System.currentTimeMillis() -
                        java.util.concurrent.TimeUnit.DAYS
                            .toMillis(7),
                )
            } else {
                cutoff
            }
        cursor.edit().putInt(root.name, sweepCache(root, offset, store, safeCutoff)).apply()
    }
}

private suspend fun sweepCache(
    root: File,
    offset: Int,
    store: FileBrowserStore,
    cutoff: Long,
): Int {
    var visited = 0
    var processed = 0
    Files.walk(root.toPath(), 4).use { paths ->
        val iterator = paths.iterator()
        while (iterator.hasNext() && processed < 512) {
            currentCoroutineContext().ensureActive()
            val file = iterator.next().toFile()
            if (visited++ < offset) continue
            processed++
            PrivateCacheUse.removeIfUnused(file) { mayDeleteCache(file, root, store, cutoff) }
        }
        return if (iterator.hasNext()) visited else 0
    }
}

private suspend fun mayDeleteCache(
    file: File,
    root: File,
    store: FileBrowserStore,
    cutoff: Long,
): Boolean =
    when {
        !Files.isRegularFile(file.toPath()) || Files.isSymbolicLink(file.toPath()) -> false
        retainedIntake(file, root) || store.referencesCache(file.absolutePath) -> false
        root.name == "resources-v2" && isDownloadAttemptTarget(file, root) -> true
        else ->
            when (mayDeleteCheckpoint(file, root, store)) {
                true -> true
                false -> false
                null -> file.lastModified() < cutoff && mayDeleteUploadSource(file, root, store)
            }
    }

private suspend fun mayDeleteCheckpoint(
    file: File,
    root: File,
    store: FileBrowserStore,
): Boolean? =
    checkpointTransferId(file)?.let { transferId ->
        val transfer = store.transfer(transferId)
        val cancelledOrMissingDownload =
            transfer == null ||
                (
                    transfer.direction == TransferDirection.DOWNLOAD.name &&
                        transfer.state == TransferState.CANCELLED.name
                )
        when {
            checkpointMustRemain(transfer) -> false
            isOrdinaryResourceCacheFile(file, root) && cancelledOrMissingDownload -> true
            else -> null
        }
    }

private suspend fun mayDeleteUploadSource(
    file: File,
    root: File,
    store: FileBrowserStore,
): Boolean =
    if (root.name != "upload-sources") {
        true
    } else {
        val transferId = decodeCacheId(file.parentFile?.name.orEmpty())
        val transfer = transferId?.let { store.transfer(it) }
        transfer == null || transfer.state in setOf("SUCCEEDED", "CANCELLED")
    }

private fun checkpointMustRemain(transfer: eu.opencloud.android.next.core.database.TransferEntity?): Boolean =
    transfer != null &&
        transfer.state !in setOf(TransferState.SUCCEEDED.name, TransferState.CANCELLED.name)

private fun isDownloadAttemptTarget(
    file: File,
    root: File,
): Boolean =
    when {
        !isOrdinaryResourceCacheFile(file, root) -> false
        else ->
            DOWNLOAD_ATTEMPT_TARGET
                .matchEntire(file.name)
                ?.groupValues
                ?.get(1)
                ?.let { encodedTransferId ->
                    decodeCacheId(encodedTransferId)?.let { cacheIdentity(it) == encodedTransferId } ?: false
                } ?: false
    }

private fun checkpointTransferId(file: File): String? {
    val encoded =
        when {
            file.name.endsWith(".part") -> file.name.removeSuffix(".part")
            file.name.endsWith(".validator") -> file.name.removeSuffix(".validator")
            else -> return null
        }
    return decodeCacheId(encoded)?.takeIf { cacheIdentity(it) == encoded }
}

private fun isOrdinaryResourceCacheFile(
    file: File,
    root: File,
): Boolean =
    if (root.name !in setOf("resources", "resources-v2")) {
        false
    } else {
        runCatching {
            val relative =
                root
                    .toPath()
                    .toAbsolutePath()
                    .normalize()
                    .relativize(file.toPath().toAbsolutePath().normalize())
            relative.nameCount == 3 &&
                relative.none { it.toString() == ".." } &&
                isCanonicalCacheId(relative.getName(0).toString()) &&
                isCanonicalCacheId(relative.getName(1).toString())
        }.getOrDefault(false)
    }

private fun isCanonicalCacheId(value: String): Boolean =
    decodeCacheId(value)?.let { cacheIdentity(it) == value } ?: false

/** A saved intake batch is a recoverable user draft, not an orphan, even before it has transfer rows. */
private fun retainedIntake(
    file: File,
    root: File,
): Boolean {
    if (root.name != "incoming-shares") return false
    val relative = root.toPath().relativize(file.toPath())
    val batch = File(root, relative.getName(0).toString())
    return relative.nameCount >= 2 && hasSavedAtomicFile(AtomicFile(File(batch, "manifest.json")))
}

private fun decodeCacheId(value: String): String? =
    if (!value.startsWith("id-")) {
        null
    } else {
        try {
            String(Base64.getUrlDecoder().decode(value.removePrefix("id-")))
        } catch (_: IllegalArgumentException) {
            null
        }
    }

private val DOWNLOAD_ATTEMPT_TARGET =
    Regex("^download-attempt-(id-[A-Za-z0-9_-]+)\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
