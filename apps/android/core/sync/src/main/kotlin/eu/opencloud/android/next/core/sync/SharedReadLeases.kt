package eu.opencloud.android.next.core.sync

import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/** Retention hints only: these never grant access or prevent explicit account/scope removal. */
internal object SharedReadLeases {
    private val readers = mutableMapOf<String, MutableMap<String, Int>>()

    @Synchronized
    fun acquire(
        account: File,
        path: String,
    ): AutoCloseable {
        val key = account.canonicalPath
        val paths = readers.getOrPut(key) { mutableMapOf() }
        paths[path] = paths.getOrDefault(path, 0) + 1
        val closed = AtomicBoolean()
        return AutoCloseable {
            if (closed.compareAndSet(false, true)) release(key, path)
        }
    }

    @Synchronized
    fun protectedPaths(account: File): List<String> = readers[account.canonicalPath]?.keys?.toList().orEmpty()

    @Synchronized
    private fun release(
        account: String,
        path: String,
    ) {
        val paths = readers[account] ?: return
        val remaining = paths.getOrDefault(path, 0) - 1
        if (remaining > 0) paths[path] = remaining else paths.remove(path)
        if (paths.isEmpty()) readers.remove(account)
    }
}
