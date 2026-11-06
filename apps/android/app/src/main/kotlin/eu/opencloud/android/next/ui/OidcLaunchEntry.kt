package eu.opencloud.android.next.ui

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import eu.opencloud.android.next.LaunchRequest

@Composable
internal fun OidcLaunchEntry(
    request: LaunchRequest?,
    restoringSession: Boolean,
    consume: (Long) -> Boolean,
    complete: (String) -> Unit,
) {
    // Capture this event's claim/handoff together; a replacement event supplies a new bundle.
    val callbacks = remember(request?.id, restoringSession) { OidcLaunchCallbacks(consume, complete) }
    LaunchedEffect(request?.id, restoringSession) {
        if (request != null && !restoringSession && callbacks.consume(request.id)) {
            // Claim and hand off synchronously. AuthViewModel owns the job across lock/recreation;
            // its existing pending-login state remains the single-use protocol authority.
            callbacks.complete(request.uri)
        }
    }
}

private class OidcLaunchCallbacks(
    val consume: (Long) -> Boolean,
    val complete: (String) -> Unit,
)
