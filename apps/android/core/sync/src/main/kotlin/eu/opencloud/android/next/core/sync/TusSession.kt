package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.TransferHttpException

internal data class TusSession(
    val url: String,
    val offset: Long,
)

/** An expired session address must be forgotten durably before a replacement is created. */
internal suspend fun openTusSession(
    url: String?,
    offset: (String) -> Long,
    create: () -> String,
    reset: suspend () -> Unit,
): TusSession {
    val position =
        if (url == null) {
            null
        } else {
            try {
                offset(url)
            } catch (failure: TransferHttpException) {
                if (failure.statusCode !in setOf(404, 410)) throw failure
                reset()
                null
            }
        }
    return if (url != null && position != null) TusSession(url, position) else TusSession(create(), 0)
}
