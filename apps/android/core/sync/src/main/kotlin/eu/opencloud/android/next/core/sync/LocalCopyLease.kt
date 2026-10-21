package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

/** Protects a file from routine cleanup; callers must separately authorize and validate every open. */
class LocalCopyLease internal constructor(
    private val release: suspend () -> Unit,
) {
    private val closed = AtomicBoolean(false)

    suspend fun close() =
        withContext(NonCancellable) {
            if (closed.compareAndSet(false, true)) release()
        }

    companion object {
        suspend fun acquire(file: File): LocalCopyLease = PrivateCacheUse.acquire(listOf(file))

        suspend fun <T> read(
            file: File,
            action: suspend () -> T,
        ): T = PrivateCacheUse.hold(listOf(file), action)
    }
}
