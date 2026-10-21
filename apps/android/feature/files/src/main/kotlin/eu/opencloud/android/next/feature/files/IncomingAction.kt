package eu.opencloud.android.next.feature.files

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Cancellation must leave the draft recoverable without publishing a stale error to the screen. */
@Suppress("TooGenericExceptionCaught")
internal suspend fun incomingAction(
    action: suspend () -> Unit,
    failed: (Exception) -> Unit,
) {
    try {
        action()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (failure: Exception) {
        currentCoroutineContext().ensureActive()
        failed(failure)
    }
}
