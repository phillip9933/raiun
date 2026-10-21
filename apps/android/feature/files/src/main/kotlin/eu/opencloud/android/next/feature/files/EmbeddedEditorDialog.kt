package eu.opencloud.android.next.feature.files

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.EmbeddedWebAppMode
import eu.opencloud.android.next.core.network.EmbeddedWebAppSession
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.sync.EmbeddedHostController
import eu.opencloud.android.next.core.sync.EmbeddedSessionSurface
import eu.opencloud.android.next.core.sync.ServerWebAppChoice
import eu.opencloud.android.next.core.sync.ServerWebApps

@Composable
internal fun EmbeddedEditorDialog(
    resource: ResourceEntity,
    choice: ServerWebAppChoice,
    mode: EmbeddedWebAppMode,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    val dismiss by rememberUpdatedState(onDismiss)
    var error by remember { mutableStateOf<String?>(null) }
    var preparing by remember { mutableStateOf(true) }
    val surface =
        remember { EditorWebSurface(context, choice.provider.appsUrl, onFailure = { error = it.safeMessage(context) }) }
    val controller =
        remember {
            EmbeddedHostController(
                scope,
                object : EmbeddedSessionSurface<EmbeddedWebAppSession> {
                    override fun show(session: EmbeddedWebAppSession) {
                        surface.show(session)
                        preparing = false
                    }

                    override fun close() = surface.close()
                },
                { ServerWebApps(context).prepareEmbedded(resource, choice, mode) },
                {
                    error = it.safeMessage(context)
                    preparing = false
                },
            )
        }
    DisposableEffect(controller, owner) {
        fun close() {
            controller.close()
            dismiss()
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
        owner.lifecycle.addObserver(observer)
        ContextCompat.registerReceiver(
            context,
            receiver,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        if (owner.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) controller.start() else close()
        onDispose {
            context.unregisterReceiver(receiver)
            owner.lifecycle.removeObserver(observer)
            controller.close()
        }
    }
    DisposableEffect(error) {
        if (error != null) controller.close()
        onDispose { }
    }
    Dialog(
        onDismissRequest = {
            controller.close()
            onDismiss()
        },
        properties =
            DialogProperties(
                usePlatformDefaultWidth = false,
                dismissOnClickOutside = false,
                securePolicy = SecureFlagPolicy.SecureOn,
            ),
    ) {
        Surface(Modifier.fillMaxSize()) {
            Column {
                Row(Modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingSm)) {
                    Text(
                        resource.name,
                        Modifier.weight(1f).padding(vertical = OpenCloudDimensions.SpacingMd),
                        maxLines = 1,
                    )
                    TextButton(onClick = {
                        controller.close()
                        onDismiss()
                    }) { Text(stringResource(R.string.document_close)) }
                }
                if (preparing &&
                    error == null
                ) {
                    CircularProgressIndicator(Modifier.padding(OpenCloudDimensions.SpacingMd))
                }
                error?.let { Text(it, Modifier.padding(OpenCloudDimensions.SpacingMd)) }
                AndroidView(factory = { surface.container }, modifier = Modifier.weight(1f).fillMaxWidth())
            }
        }
    }
}
