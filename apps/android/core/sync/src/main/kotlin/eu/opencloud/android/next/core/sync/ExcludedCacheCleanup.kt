package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileBrowserDatabase
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption

/** Retry leased or failed removals on the next sweep, including after process restart. */
internal suspend fun reclaimExcludedCache(
    database: FileBrowserDatabase,
    filesDir: File,
) {
    val queue = database.excludedCacheDao()
    val roots = listOf("resources", "resources-v2").map { File(filesDir, it).toPath().toAbsolutePath().normalize() }
    queue.pending().forEach { entry ->
        currentCoroutineContext().ensureActive()
        val file = File(entry.path)
        val path = file.toPath().toAbsolutePath().normalize()
        val root = roots.firstOrNull { path != it && path.startsWith(it) }
        val safe =
            root != null &&
                generateSequence(path) { it.parent }
                    .takeWhile { it != root.parent }
                    .none { Files.isSymbolicLink(it) }
        if (!safe) {
            // Never act on a stale/corrupt path outside the ordinary resource cache.
            queue.forget(entry.path)
        } else {
            PrivateCacheUse.ifUnused(file) {
                if (database.resourceDao().referencesCache(entry.path)) {
                    queue.forget(entry.path)
                } else if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS) ||
                    (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && file.delete())
                ) {
                    queue.forget(entry.path)
                }
                true
            }
            // Retained entries go behind untouched work so busy readers cannot starve later batches.
            queue.defer(entry.path)
        }
    }
}
