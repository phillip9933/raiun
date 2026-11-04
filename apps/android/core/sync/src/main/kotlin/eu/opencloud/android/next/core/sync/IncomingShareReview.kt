package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.os.CancellationSignal
import android.provider.OpenableColumns
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume

/** Provider-supplied metadata is untrusted and never identifies the original sending app. */
data class IncomingShareReview(
    val name: String? = null,
    val providerPackage: String? = null,
)

// A provider that ignores cancellation occupies at most one daemon worker. Only one batch may queue.
private val reviewWorker =
    ThreadPoolExecutor(0, 1, 10, TimeUnit.SECONDS, ArrayBlockingQueue(1), { work ->
        Thread(work, "incoming-share-review").apply { isDaemon = true }
    })

// Cancellation itself can invoke remote provider code; keep it off the deadline and UI threads.
private val reviewCancellationWorker =
    ThreadPoolExecutor(0, 1, 10, TimeUnit.SECONDS, SynchronousQueue(), { work ->
        Thread(work, "incoming-share-review-cancel").apply { isDaemon = true }
    })
private val reviewDeadline =
    ScheduledThreadPoolExecutor(1) { work ->
        Thread(work, "incoming-share-review-deadline").apply { isDaemon = true }
    }.apply { removeOnCancelPolicy = true }

internal suspend fun reviewIncomingShareMetadata(
    context: Context,
    sources: List<Uri>,
    timeoutMillis: Long = 5_000,
): List<IncomingShareReview> =
    suspendCancellableCoroutine { continuation ->
        val rows = MutableList(sources.size) { IncomingShareReview() }
        val finished = AtomicBoolean(false)
        val signal = CancellationSignal()
        val task = AtomicReference<Future<*>?>()
        val finish = {
            if (finished.compareAndSet(false, true)) {
                continuation.resume(synchronized(rows) { rows.toList() })
            }
        }
        val deadline =
            reviewDeadline.schedule({
                finish()
                cancelReview(task.get())
                cancelReviewSignal(signal)
            }, timeoutMillis, TimeUnit.MILLISECONDS)
        continuation.invokeOnCancellation {
            finished.set(true)
            deadline.cancel(false)
            cancelReview(task.get())
            cancelReviewSignal(signal)
        }
        try {
            task.set(
                reviewWorker.submit {
                    try {
                        sources.forEachIndexed { index, uri ->
                            if (finished.get()) return@submit
                            val row = readReviewMetadata(context, uri, signal)
                            synchronized(rows) { rows[index] = row }
                        }
                    } finally {
                        finish()
                        deadline.cancel(false)
                    }
                },
            )
            if (finished.get()) cancelReview(task.get())
        } catch (_: RejectedExecutionException) {
            deadline.cancel(false)
            finish()
        }
    }

private fun cancelReviewSignal(signal: CancellationSignal) {
    try {
        reviewCancellationWorker.submit { signal.cancel() }
    } catch (_: RejectedExecutionException) {
        // An unresponsive provider cannot accumulate cancellation workers or block later deadlines.
    }
}

private fun cancelReview(task: Future<*>?) {
    task?.cancel(true)
    if (task is Runnable) reviewWorker.remove(task)
}

@Suppress("TooGenericExceptionCaught") // Optional metadata from external providers must fail closed to unknown.
private fun readReviewMetadata(
    context: Context,
    uri: Uri,
    signal: CancellationSignal,
): IncomingShareReview {
    val provider =
        try {
            context.packageManager
                .resolveContentProvider(uri.authority?.substringAfterLast('@').orEmpty(), 0)
                ?.packageName
                ?.takeIf { it.length <= 255 && it.matches(Regex("[A-Za-z0-9_.]+")) }
        } catch (_: RuntimeException) {
            null
        }
    val name =
        try {
            context.contentResolver
                .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null, signal)
                ?.use {
                    val column = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (column >= 0 && it.moveToFirst() && !it.isNull(column)) it.getString(column) else null
                }?.takeIf { value ->
                    value.isNotBlank() &&
                        value.length <= 255 &&
                        value !in setOf(".", "..") &&
                        value.none {
                            it == '/' ||
                                it == '\\' ||
                                it.isISOControl() ||
                                Character.getType(it) == Character.FORMAT.toInt()
                        }
                }
        } catch (_: RuntimeException) {
            null
        }
    return IncomingShareReview(name, provider)
}
