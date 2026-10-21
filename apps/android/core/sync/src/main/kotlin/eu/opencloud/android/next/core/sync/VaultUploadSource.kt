package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.os.CancellationSignal
import android.system.Os
import android.system.StructPollfd
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Cancels provider opens and polls pipe reads without staging any plaintext on disk. */
suspend fun <T> withCancellableVaultUploadSource(
    context: Context,
    uri: Uri,
    pollReady: (StructPollfd, Int) -> Boolean = { descriptor, timeout -> Os.poll(arrayOf(descriptor), timeout) > 0 },
    block: suspend (InputStream) -> T,
): T =
    withVaultUploadSource(
        { signal, stopped -> openIncomingUploadSource(context, uri, signal, stopped, pollReady) },
        block,
    )

@OptIn(InternalCoroutinesApi::class)
internal suspend fun <T> withVaultUploadSource(
    open: (CancellationSignal, () -> Boolean) -> InputStream,
    block: suspend (InputStream) -> T,
): T {
    val signal = CancellationSignal()
    val stopped = AtomicBoolean(false)
    val input = AtomicReference<InputStream?>()
    val deadline = AtomicReference<ScheduledFuture<*>?>()
    val stop = {
        stopped.set(true)
        runCatching { signal.cancel() }
        runCatching { input.getAndSet(null)?.close() }
        Unit
    }
    val arm = {
        deadline.getAndSet(vaultSourceWatchdog.schedule(stop, 60, TimeUnit.SECONDS))?.cancel(false)
        Unit
    }
    val coroutine = currentCoroutineContext()
    val cancellation = coroutine[Job]?.invokeOnCompletion(onCancelling = true, invokeImmediately = true) { stop() }
    try {
        coroutine.ensureActive()
        arm()
        val opened = open(signal, stopped::get)
        input.set(opened)
        coroutine.ensureActive()
        if (stopped.get()) throw OpenCloudException(OpenCloudError.SourceUnavailable)
        val guarded =
            object : FilterInputStream(opened) {
                override fun read(): Int = checkedRead { opened.read() }

                override fun read(
                    bytes: ByteArray,
                    offset: Int,
                    length: Int,
                ): Int = checkedRead { opened.read(bytes, offset, length) }

                @Suppress("ThrowsCount") // Cancellation and timeout must reject EOF before any durable job is accepted.
                private fun checkedRead(read: () -> Int): Int {
                    coroutine.ensureActive()
                    if (stopped.get()) throw OpenCloudException(OpenCloudError.SourceUnavailable)
                    arm()
                    val result =
                        try {
                            read()
                        } catch (failure: IOException) {
                            coroutine.ensureActive()
                            if (stopped.get()) throw OpenCloudException(OpenCloudError.SourceUnavailable)
                            throw failure
                        }
                    coroutine.ensureActive()
                    if (stopped.get()) throw OpenCloudException(OpenCloudError.SourceUnavailable)
                    deadline.getAndSet(null)?.cancel(false)
                    return result
                }
            }
        return block(guarded).also { coroutine.ensureActive() }
    } finally {
        cancellation?.dispose()
        deadline.getAndSet(null)?.cancel(false)
        stop()
    }
}

private val vaultSourceWatchdog =
    ScheduledThreadPoolExecutor(1) { task ->
        Thread(task, "vault-source-watchdog").apply { isDaemon = true }
    }.apply { removeOnCancelPolicy = true }
