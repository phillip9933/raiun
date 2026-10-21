package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Cancel the underlying blocking HTTP call as soon as its owning coroutine is cancelled. */
@OptIn(InternalCoroutinesApi::class)
internal suspend fun <T> withBoundaryRequestCancellation(
    cancel: () -> Unit,
    block: suspend () -> T,
): T {
    val context = currentCoroutineContext()
    context.ensureActive()
    val registration =
        requireNotNull(context[Job]).invokeOnCompletion(onCancelling = true, invokeImmediately = true) {
            if (it != null) cancel()
        }
    return try {
        block()
    } finally {
        registration.dispose()
    }
}
