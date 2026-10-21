package eu.opencloud.android.next.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.ui.BrowserContent
import eu.opencloud.android.next.core.ui.BrowserEntry
import eu.opencloud.android.next.core.ui.BrowserPlacementBar
import eu.opencloud.android.next.core.ui.BrowserPlacementBarState
import eu.opencloud.android.next.core.ui.FileNameConflictDialog

// Modal state branches correspond to separate confirmation and unlock windows.

/** Uses the same folder rows and placement controls for ordinary and encrypted destinations. */
@Suppress("CyclomaticComplexMethod")
@Composable
internal fun BoundaryDestinationDialog(
    request: BoundaryTransferRequest,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val controller = remember(request) { BoundaryDestinationController(context.applicationContext, request) }
    val state by controller.state.collectAsState()
    val settings by remember(context) { SettingsRepository.create(context).settings }.collectAsState(UserSettings())
    val currentDismiss by rememberUpdatedState(onDismiss)
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    var disclosePlaintext by remember { mutableStateOf(false) }
    var confirmCancel by remember { mutableStateOf(false) }
    val dismiss = {
        if (state.transferring) confirmCancel = true else onDismiss()
    }
    DisposableEffect(controller, lifecycle) {
        val observer =
            LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_STOP) {
                    controller.close()
                    currentDismiss()
                }
            }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            controller.close()
        }
    }
    Dialog(
        onDismissRequest = dismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn, usePlatformDefaultWidth = false),
    ) {
        Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
            Column(Modifier.fillMaxSize()) {
                BoundaryDestinationHeader(state, controller::up, dismiss)
                if (state.loading ||
                    state.transferring
                ) {
                    CircularProgressIndicator(Modifier.padding(OpenCloudDimensions.SpacingMd))
                }
                if (state.transferring) {
                    Text(
                        stringResource(R.string.boundary_working),
                        Modifier.padding(OpenCloudDimensions.SpacingMd),
                    )
                }
                BoundaryDestinationNotice(state)
                if (state.complete) {
                    TextButton(onClick = onDismiss) { Text(stringResource(R.string.boundary_close)) }
                } else {
                    BoundaryDestinationItems(state, settings.browserLayout, controller, Modifier.weight(1f))
                    if (state.location != null && state.unlock == null) {
                        BoundaryPlacementFooter(state, request, onCancel = dismiss) {
                            if (state.plaintextWarning) disclosePlaintext = true else controller.transfer()
                        }
                    }
                }
            }
        }
    }
    state.unlock?.let { location ->
        key(location.canonicalServer, location.driveId, location.remoteVaultId) {
            BoundaryUnlockDialog(location.title, state.loading, state.error?.safeMessage(context), controller::unlock) {
                controller.loadLocations()
            }
        }
    }
    state.conflict?.let { conflict ->
        FileNameConflictDialog(
            name = conflict.name,
            proposedName = conflict.proposedName,
            busy = state.transferring,
            secureWindow = true,
            onKeepBoth = controller::keepBoth,
            onCancel = controller::cancelConflict,
        )
    }
    if (disclosePlaintext) {
        BoundaryConfirmationDialog(
            if (request.move) R.string.boundary_plaintext_move_title else R.string.boundary_plaintext_title,
            if (request.move) R.string.boundary_plaintext_move_body else R.string.boundary_plaintext_body,
            onConfirm = {
                disclosePlaintext = false
                controller.transfer()
            },
            onDismiss = { disclosePlaintext = false },
        )
    }
    if (confirmCancel) {
        BoundaryConfirmationDialog(R.string.boundary_cancel_title, R.string.boundary_cancel_body, onConfirm = {
            confirmCancel = false
            controller.close()
            onDismiss()
        }, onDismiss = { confirmCancel = false })
    }
}

@Composable
private fun BoundaryDestinationHeader(
    state: BoundaryDestinationState,
    up: () -> Unit,
    dismiss: () -> Unit,
) {
    Row(Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingSm)) {
        if (state.location != null && !state.transferring && !state.complete) {
            IconButton(
                onClick = up,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.boundary_locations)) }
        }
        Column(Modifier.weight(1f)) {
            Text(stringResource(R.string.boundary_destination_title), style = MaterialTheme.typography.titleLarge)
            state.location?.let { Text(listOf(it.title, state.path).filter(String::isNotEmpty).joinToString(" / ")) }
        }
        TextButton(onClick = dismiss) { Text(stringResource(R.string.boundary_close)) }
    }
}

@Composable
private fun BoundaryDestinationNotice(state: BoundaryDestinationState) {
    val context = LocalContext.current
    val message =
        when {
            state.complete -> stringResource(R.string.boundary_complete)
            state.incompleteMove -> stringResource(R.string.boundary_partial_move)
            state.incompleteDestination -> stringResource(R.string.boundary_partial_copy)
            state.unlock != null -> null
            else -> state.error?.safeMessage(context)
        }
    Column {
        message?.let {
            Text(
                it,
                Modifier.padding(OpenCloudDimensions.SpacingMd),
                color = MaterialTheme.colorScheme.onSurface,
            )
        }
        if (state.incompleteMove || state.incompleteDestination) {
            state.error?.let {
                Text(
                    it.safeMessage(context),
                    Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd),
                )
            }
        }
    }
}

@Composable
private fun BoundaryDestinationItems(
    state: BoundaryDestinationState,
    layout: SettingsBrowserLayout,
    controller: BoundaryDestinationController,
    modifier: Modifier = Modifier,
) {
    if (state.location == null) {
        BrowserContent(state.locations, key = {
            "${it.kind}:${it.driveId}:${it.vaultPath}"
        }, layout = layout, modifier = modifier) { location ->
            BoundaryDestinationRow(
                location.title,
                location.isVaultRoot,
                layout,
                enabled =
                    !state.loading && !state.transferring,
            ) { controller.select(location) }
        }
    } else {
        BrowserContent(state.folders, key = { it.id }, layout = layout, modifier = modifier, notice = {
            if (!state.loading &&
                state.folders.isEmpty()
            ) {
                Text(stringResource(R.string.boundary_empty), Modifier.padding(OpenCloudDimensions.SpacingMd))
            }
        }) { folder ->
            BoundaryDestinationRow(
                folder.name,
                folder.vault != null,
                layout,
                enabled =
                    !state.loading && !state.transferring,
            ) { controller.open(folder) }
        }
    }
}

@Composable
private fun BoundaryDestinationRow(
    name: String,
    encrypted: Boolean,
    layout: SettingsBrowserLayout,
    enabled: Boolean,
    onOpen: () -> Unit,
) {
    BrowserEntry(
        layout = layout,
        onOpen = { if (enabled) onOpen() },
        name = { Text(name, maxLines = 1) },
        thumbnail = { modifier ->
            Icon(
                if (encrypted) Icons.Default.Lock else Icons.Default.Folder,
                null,
                modifier.padding(OpenCloudDimensions.SpacingMd),
            )
        },
        metadata = {
            Text(stringResource(if (encrypted) R.string.boundary_encrypted else R.string.boundary_ordinary))
        },
        actions = {},
    )
}

@Composable
private fun BoundaryPlacementFooter(
    state: BoundaryDestinationState,
    request: BoundaryTransferRequest,
    onCancel: () -> Unit,
    onPlace: () -> Unit,
) {
    BrowserPlacementBar(
        sourceSummary =
            if (request.ordinary.size >
                1
            ) {
                pluralStringResource(R.plurals.boundary_selection_count, request.ordinary.size, request.ordinary.size)
            } else {
                request.unlocked?.second?.name
                    ?: request.ordinary
                        .firstOrNull()
                        ?.name
                        .orEmpty()
            },
        state =
            BrowserPlacementBarState(
                actionLabel = if (request.move) R.string.boundary_move_here else R.string.boundary_copy_here,
                cancelLabel = R.string.boundary_cancel,
                busy = state.loading || state.transferring,
                enabled = state.error == null && !state.transferring,
            ),
        onPlace = onPlace,
        onCancel = onCancel,
    )
}

@Composable
private fun BoundaryUnlockDialog(
    title: String,
    busy: Boolean,
    error: String?,
    unlock: (CharArray) -> Unit,
    dismiss: () -> Unit,
) {
    var password by remember(title) { mutableStateOf("") }
    var visible by remember(title) { mutableStateOf(false) }
    val cancel = {
        password = ""
        dismiss()
    }
    AlertDialog(onDismissRequest = {
        if (!busy) cancel()
    }, title = { Text(stringResource(R.string.boundary_unlock)) }, text = {
        Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
            Text(title)
            OutlinedTextField(
                value = password,
                onValueChange = {
                    password = it
                },
                enabled = !busy,
                label = {
                    Text(stringResource(R.string.boundary_password))
                },
                visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                trailingIcon = {
                    IconButton(onClick = { visible = !visible }, enabled = !busy) {
                        Icon(
                            if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            stringResource(if (visible) R.string.vault_hide_password else R.string.vault_show_password),
                        )
                    }
                },
            )
            error?.let { Text(it) }
        }
    }, confirmButton = {
        TextButton(onClick = {
            val value = password.toCharArray()
            password = ""
            unlock(value)
        }, enabled = !busy && password.isNotEmpty()) { Text(stringResource(R.string.boundary_unlock_action)) }
    }, dismissButton = {
        TextButton(onClick = cancel, enabled = !busy) { Text(stringResource(R.string.boundary_cancel)) }
    }, properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn))
}

@Composable
private fun BoundaryConfirmationDialog(
    title: Int,
    body: Int,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(onDismissRequest = onDismiss, title = {
        Text(stringResource(title))
    }, text = { Text(stringResource(body)) }, confirmButton = {
        TextButton(onClick = onConfirm) { Text(stringResource(R.string.boundary_continue)) }
    }, dismissButton = {
        TextButton(onClick = onDismiss) {
            Text(stringResource(R.string.boundary_cancel))
        }
    }, properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn))
}
