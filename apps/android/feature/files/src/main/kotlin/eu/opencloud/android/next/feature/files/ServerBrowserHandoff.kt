package eu.opencloud.android.next.feature.files

import android.content.ActivityNotFoundException
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.Uri
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.sync.BrowserHandoffController
import eu.opencloud.android.next.core.sync.ServerWebAppChoice
import eu.opencloud.android.next.core.sync.ServerWebApps

internal class ServerBrowserHandoff(
    val opening: Boolean,
    val open: (ServerWebAppChoice) -> Unit,
)

/** Browser recovery always requests a new server grant after the old embedded surface has closed. */
@Composable
internal fun rememberServerBrowserHandoff(
    resource: ResourceEntity,
    onError: (String) -> Unit,
    onLaunch: () -> Unit,
    beforeOpen: () -> Unit = {},
): ServerBrowserHandoff {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    val error by rememberUpdatedState(onError)
    val launched by rememberUpdatedState(onLaunch)
    val prepare by rememberUpdatedState(beforeOpen)
    var opening by remember(resource) { mutableStateOf(false) }
    var controller by remember(resource) { mutableStateOf<BrowserHandoffController?>(null) }
    DisposableEffect(resource, lifecycle) {
        fun close() {
            controller?.close()
            opening = false
        }
        val observer =
            LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_PAUSE || event == Lifecycle.Event.ON_DESTROY) close()
            }
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(
                    context: Context?,
                    intent: Intent?,
                ) = close()
            }
        lifecycle.addObserver(observer)
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        onDispose {
            lifecycle.removeObserver(observer)
            context.unregisterReceiver(receiver)
            close()
        }
    }
    return ServerBrowserHandoff(opening) { choice ->
        if (!opening && lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
            prepare()
            controller?.close()
            opening = true
            controller =
                BrowserHandoffController(
                    scope,
                    { ServerWebApps(context).prepareBrowser(resource, choice) },
                    { url ->
                        if (!lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) {
                            false
                        } else {
                            try {
                                context.startActivity(
                                    Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE),
                                )
                                opening = false
                                launched()
                                true
                            } catch (_: ActivityNotFoundException) {
                                false
                            }
                        }
                    },
                    {
                        opening = false
                        error(context.localizedString(R.string.document_browser_required))
                    },
                    {
                        opening = false
                        error(it.safeMessage(context))
                    },
                ).also { it.start() }
        }
    }
}
