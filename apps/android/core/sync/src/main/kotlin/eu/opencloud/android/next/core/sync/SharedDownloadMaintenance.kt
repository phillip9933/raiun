package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileBrowserDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/** Reclaims interrupted staging files and copies whose scope metadata has been removed. */
class SharedDownloadMaintenance(
    private val database: FileBrowserDatabase,
    private val filesDir: File,
) {
    private val localFiles = database.sharedLocalFileDao()

    suspend fun expireTemporary(
        hours: Int,
        now: Long,
    ): Int {
        require(hours >= 0)
        return if (hours == 0) 0 else removeTemporary(now - hours * 3_600_000L)
    }

    suspend fun clearTemporary(): Int = removeTemporary(null)

    private suspend fun removeTemporary(before: Long?): Int =
        withContext(Dispatchers.IO) {
            var removed = 0
            for (account in database.accountDao().allIds()) {
                SharedDownloadFiles.guard(filesDir, account) {
                    // Remove metadata first: interruption leaves an orphan for cleanup, never a reusable missing copy.
                    val directory = SharedDownloadFiles.accountDirectory(filesDir, account)
                    removed += localFiles.removeTemporary(account, before, SharedReadLeases.protectedPaths(directory))
                    SharedDownloadFiles.pruneUnreferenced(filesDir, account, localFiles.retainedPaths(account).toSet())
                }
            }
            removed
        }

    suspend fun cleanupAll(): Int =
        withContext(Dispatchers.IO) {
            var removed = 0
            for (directory in SharedDownloadFiles.accountDirectories(filesDir)) {
                removed +=
                    SharedDownloadFiles.guardDirectory(directory) {
                        // Re-read inside the writer gate, including inactive accounts and concurrent re-additions.
                        val account =
                            database.accountDao().allIds().singleOrNull {
                                SharedDownloadFiles.accountDirectory(filesDir, it) == directory
                            }
                        val retained = account?.let { localFiles.retainedPaths(it).toSet() }.orEmpty()
                        SharedDownloadFiles.pruneDirectory(directory, retained)
                    }
            }
            removed
        }

    suspend fun cleanupAccount(accountId: String): Int =
        withContext(Dispatchers.IO) {
            SharedDownloadFiles.guard(filesDir, accountId) {
                SharedDownloadFiles.pruneUnreferenced(
                    filesDir,
                    accountId,
                    database.sharedLocalFileDao().retainedPaths(accountId).toSet(),
                )
            }
        }
}
