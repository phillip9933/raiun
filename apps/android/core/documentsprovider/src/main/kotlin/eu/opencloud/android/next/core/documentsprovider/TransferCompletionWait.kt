package eu.opencloud.android.next.core.documentsprovider

import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flow
import java.io.FileNotFoundException

/** Transfer changes arrive from Room; only the revocation check needs a periodic wakeup. */
internal suspend fun awaitEditDownload(
    states: Flow<String?>,
    authorized: suspend () -> Boolean,
) {
    val revocationChecks =
        flow {
            while (true) {
                emit(Unit)
                delay(250)
            }
        }
    states
        .combine(revocationChecks) { state, _ ->
            currentCoroutineContext().ensureActive()
            check(authorized()) { "Document editing is unavailable or locked." }
            when (state) {
                null -> throw FileNotFoundException("Download unavailable.")
                "SUCCEEDED" -> true
                "QUEUED", "RUNNING", "RETRY" -> false
                else -> throw FileNotFoundException("The document download did not complete.")
            }
        }.first { it }
}
