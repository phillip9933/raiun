package eu.opencloud.android.next.feature.files

import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.network.EmbeddedWebAppMode
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.ServerWebAppChoice
import eu.opencloud.android.next.core.sync.ServerWebApps
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch

@Composable
@Suppress("FunctionNaming", "TooGenericExceptionCaught", "ktlint:standard:function-naming")
internal fun ServerWebAppDialog(
    resource: ResourceEntity,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val service = remember(context) { ServerWebApps(context) }
    val scope = rememberCoroutineScope()
    var choices by remember(resource) { mutableStateOf<List<ServerWebAppChoice>>(emptyList()) }
    var loading by remember(resource) { mutableStateOf(true) }
    var error by remember(resource) { mutableStateOf<String?>(null) }
    var embedded by remember(resource) { mutableStateOf(false) }
    var selected by remember(resource) { mutableStateOf<Pair<ServerWebAppChoice, EmbeddedWebAppMode>?>(null) }
    val supportsEmbedded = remember { AndroidEditorProfiles.supported() }
    LaunchedEffect(resource, embedded) {
        loading = true
        error = null
        choices = emptyList()
        try {
            choices = service.choices(resource, embedded)
        } catch (failure: Exception) {
            error = failure.toOpenCloudError().safeMessage(context)
        } finally {
            loading = false
        }
    }
    selected?.let { (choice, mode) ->
        EmbeddedEditorDialog(resource, choice, mode, onDismiss)
        return
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.document_web_open)) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text(resource.name)
                WebAppModeSelector(embedded, loading, supportsEmbedded) { embedded = it }
                WebAppLoadStatus(loading, error, choices.isEmpty())
                choices.forEach { choice ->
                    TextButton(enabled = !loading, onClick = {
                        if (embedded) {
                            selected = choice to EmbeddedWebAppMode.VIEW
                            return@TextButton
                        }
                        loading = true
                        error = null
                        scope.launch {
                            try {
                                val url = service.open(resource, choice)
                                currentCoroutineContext().ensureActive()
                                if (!AppLock(context).canOpenApp()) throw SecurityException()
                                context.startActivity(
                                    Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE),
                                )
                                onDismiss()
                            } catch (_: ActivityNotFoundException) {
                                error =
                                    context.localizedString(R.string.document_browser_required)
                            } catch (failure: Exception) {
                                error = failure.toOpenCloudError().safeMessage(context)
                            } finally {
                                loading = false
                            }
                        }
                    }) {
                        Text(
                            if (embedded) {
                                stringResource(
                                    R.string.document_view_with,
                                    choice.app.name,
                                )
                            } else {
                                choice.app.name
                            },
                        )
                    }
                    if (embedded) {
                        TextButton(enabled = !loading, onClick = { selected = choice to EmbeddedWebAppMode.WRITE }) {
                            Text(stringResource(R.string.document_edit_with, choice.app.name))
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.document_close)) } },
    )
}

@Composable
private fun WebAppModeSelector(
    embedded: Boolean,
    loading: Boolean,
    supported: Boolean,
    onChange: (Boolean) -> Unit,
) {
    Column {
        Row {
            TextButton(enabled = embedded && !loading, onClick = {
                onChange(false)
            }) { Text(stringResource(R.string.document_in_browser)) }
            TextButton(enabled = supported && !embedded && !loading, onClick = {
                onChange(true)
            }) { Text(stringResource(R.string.document_in_app)) }
        }
        if (embedded) Text(stringResource(R.string.document_session_warning))
    }
}

@Composable
private fun WebAppLoadStatus(
    loading: Boolean,
    error: String?,
    empty: Boolean,
) {
    Column {
        if (loading) CircularProgressIndicator()
        error?.let { Text(it) }
        if (!loading && error == null && empty) Text(stringResource(R.string.document_no_web_apps))
    }
}
