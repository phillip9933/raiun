package eu.opencloud.android.next.feature.files

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import kotlinx.coroutines.delay

/** Avoid flashing the pull indicator for fast automatic folder refreshes. */
@Composable
internal fun delayedRefreshIndicator(
    refreshing: Boolean,
    location: Any?,
): Boolean {
    val visible by produceState(false, refreshing, location) {
        value = false
        if (refreshing) {
            delay(400)
            value = true
        }
    }
    return refreshing && visible
}
