package eu.opencloud.android.next.core.ui

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AddToHomeScreen
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.sync.FolderShortcuts
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Suppress("TooGenericExceptionCaught") // User-visible failure boundary for launcher and folder availability.
@Composable
fun FolderShortcutAction(pin: suspend (android.graphics.Bitmap) -> Boolean) {
    val context = LocalContext.current
    val shortcuts = remember { FolderShortcuts(context.applicationContext) }
    val scope = rememberCoroutineScope()
    var message by remember { mutableStateOf<Int?>(null) }
    var busy by remember { mutableStateOf(false) }
    var imported by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var choosing by remember { mutableStateOf(false) }
    var color by remember { mutableStateOf(eu.opencloud.android.next.core.sync.FolderIconColor.DEFAULT) }
    var image by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    val picker =
        androidx.activity.compose.rememberLauncherForActivityResult(
            androidx.activity.result.contract.ActivityResultContracts
                .OpenDocument(),
        ) { uri ->
            if (uri != null) {
                scope.launch {
                    busy = true
                    try {
                        imported =
                            withContext(
                                Dispatchers.IO,
                            ) {
                                eu.opencloud.android.next.core.sync.FolderShortcutIcon
                                    .readImage(context, uri)
                            }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        message = R.string.folder_shortcut_image_error
                    } finally {
                        busy = false
                    }
                }
            }
        }
    if (shortcuts.supported()) {
        BrowserAction(stringResource(R.string.folder_shortcut_add), Icons.Outlined.AddToHomeScreen) {
            choosing = true
        }
    }
    imported?.let { source ->
        FolderIconCropDialog(source, onCancel = { imported = null }, onApply = { cropped ->
            image = cropped
            imported = null
        })
    }
    if (choosing && imported == null) {
        FolderShortcutPicker(color, image, busy, {
            color = it
            image = null
        }, { picker.launch(arrayOf("image/*")) }, onPin = {
            if (!busy) {
                scope.launch {
                    busy = true
                    try {
                        val requested =
                            withContext(Dispatchers.IO) {
                                pin(
                                    eu.opencloud.android.next.core.sync.FolderShortcutIcon
                                        .render(context, color, image),
                                )
                            }
                        choosing = false
                        message = if (requested) R.string.folder_shortcut_requested else R.string.folder_shortcut_error
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        message = R.string.folder_shortcut_error
                    } finally {
                        busy = false
                    }
                }
            }
        }, onDismiss = { choosing = false })
    }
    message?.let {
        AlertDialog(
            onDismissRequest = { message = null },
            text = { Text(stringResource(it)) },
            confirmButton = {
                TextButton(
                    onClick = { message = null },
                ) { Text(stringResource(R.string.folder_shortcut_close)) }
            },
        )
    }
}
