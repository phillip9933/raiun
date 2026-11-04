package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/** Navigation metadata only. No row authorizes a content read, write or deletion. */
data class BoundaryDestinationFolder(
    val id: String,
    val path: String,
    val name: String,
    val isVaultRoot: Boolean,
)

/** One complete, globally sorted folder inventory, owned independently of source UI pages. */
interface BoundaryDestinationSnapshot : AutoCloseable {
    val totalCount: Long

    suspend fun page(
        offset: Long = 0,
        limit: Int = 128,
    ): List<BoundaryDestinationFolder>

    override fun close()
}

/** Every producer must validate all children, including filtered files, before returning. */
internal suspend fun captureBoundaryDestinationFolders(
    context: Context,
    path: String,
    guard: suspend () -> Unit,
    produce: suspend ((BoundaryDestinationFolder) -> Unit) -> Unit,
): BoundaryDestinationSnapshot {
    var index: VaultDirectoryIndex? = null
    var delivered = false
    try {
        val result =
            withContext(Dispatchers.IO) {
                currentCoroutineContext().ensureActive()
                guard()
                requireBoundaryDirectoryParent(path)
                val buildContext = currentCoroutineContext()
                val building =
                    VaultDirectoryIndex(context.noBackupFilesDir, VaultDirectoryOrder.DESTINATION) {
                        buildContext.ensureActive()
                    }
                index = building
                BoundaryNameStore(context).use { identities ->
                    produce { folder ->
                        buildContext.ensureActive()
                        requireDestinationFolder(path, folder)
                        val canonical = folder.path.trim('/')
                        if (!identities.addUnique("id\u0000${folder.id}") ||
                            !identities.addUnique("path\u0000$canonical")
                        ) {
                            throw OpenCloudException(OpenCloudError.InvalidResponse)
                        }
                        building.add(
                            VaultFolder(
                                folder.id,
                                folder.name,
                                folder.name,
                                canonical,
                                canonical,
                                true,
                                0,
                                null,
                                isVaultRoot = folder.isVaultRoot,
                            ),
                        )
                    }
                    identities.finish()
                }
                building.finish()
                guard()
                currentCoroutineContext().ensureActive()
                CapturedBoundaryDestination(building, guard)
            }
        delivered = true
        return result
    } finally {
        if (!delivered) index?.close()
    }
}

private fun requireDestinationFolder(
    parent: String,
    entry: BoundaryDestinationFolder,
) {
    val validName = entry.name.isNotBlank() && entry.name !in setOf(".", "..")
    val invalidCharacter = entry.name.any { it == '/' || it == '\\' || it.isISOControl() }
    val expected = listOf(parent.trim('/'), entry.name).filter(String::isNotEmpty).joinToString("/")
    val validUnicode = listOf(entry.id, entry.path, entry.name).all { Charsets.UTF_8.newEncoder().canEncode(it) }
    if (!validName || invalidCharacter || entry.id.isBlank()) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
    if (entry.path.trim('/') != expected || !validUnicode) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
}

private class CapturedBoundaryDestination(
    private val index: VaultDirectoryIndex,
    private val guard: suspend () -> Unit,
) : BoundaryDestinationSnapshot {
    override val totalCount: Long = index.count

    override suspend fun page(
        offset: Long,
        limit: Int,
    ): List<BoundaryDestinationFolder> {
        var delivered = false
        try {
            val result =
                withContext(Dispatchers.IO) {
                    require(offset >= 0 && limit in 1..128)
                    requireCurrent()
                    val rows =
                        index.page(offset, limit).map {
                            BoundaryDestinationFolder(it.id, it.path, it.name, it.isVaultRoot)
                        }
                    requireCurrent()
                    rows
                }
            delivered = true
            return result
        } finally {
            if (!delivered) close()
        }
    }

    private suspend fun requireCurrent() {
        index.requireOpen()
        currentCoroutineContext().ensureActive()
        guard()
        currentCoroutineContext().ensureActive()
        index.requireOpen()
    }

    override fun close() = index.close()
}
