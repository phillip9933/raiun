package eu.opencloud.android.next.core.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.FolderIconColor
import eu.opencloud.android.next.core.sync.FolderShortcutIcon

@Composable
@Suppress("LongParameterList") // Explicit icon choices and picker actions.
fun FolderShortcutPicker(
    color: FolderIconColor,
    image: Bitmap?,
    busy: Boolean,
    onColor: (FolderIconColor) -> Unit,
    onImage: () -> Unit,
    onPin: () -> Unit,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val preview = remember(color, image) { FolderShortcutIcon.preview(context, color, image) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.folder_shortcut_appearance)) },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                Image(
                    preview.asImageBitmap(),
                    stringResource(R.string.folder_shortcut_preview),
                    Modifier.size(OpenCloudDimensions.TouchTarget * 2).clip(CircleShape),
                )
                Text(stringResource(R.string.folder_shortcut_badge))
                FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                    FolderIconColor.entries.forEach { option ->
                        FilterChip(
                            selected = image == null && color == option,
                            enabled = !busy,
                            onClick = { onColor(option) },
                            label = { Text(stringResource(option.label())) },
                        )
                    }
                }
                OutlinedButton(
                    onClick = onImage,
                    enabled = !busy,
                ) { Text(stringResource(R.string.folder_shortcut_image)) }
            }
        },
        confirmButton = {
            FilledTonalButton(onClick = onPin, enabled = !busy) { Text(stringResource(R.string.folder_shortcut_add)) }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                enabled = !busy,
            ) { Text(stringResource(R.string.folder_shortcut_cancel)) }
        },
    )
}

private fun FolderIconColor.label(): Int =
    when (this) {
        FolderIconColor.DEFAULT -> R.string.folder_shortcut_default
        FolderIconColor.BLUE -> R.string.folder_shortcut_blue
        FolderIconColor.GREEN -> R.string.folder_shortcut_green
        FolderIconColor.YELLOW -> R.string.folder_shortcut_yellow
        FolderIconColor.RED -> R.string.folder_shortcut_red
        FolderIconColor.PURPLE -> R.string.folder_shortcut_purple
        FolderIconColor.ORANGE -> R.string.folder_shortcut_orange
        FolderIconColor.PINK -> R.string.folder_shortcut_pink
        FolderIconColor.TEAL -> R.string.folder_shortcut_teal
        FolderIconColor.GREY -> R.string.folder_shortcut_grey
    }
