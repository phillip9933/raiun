package eu.opencloud.android.next.feature.files

import android.graphics.Bitmap
import androidx.compose.runtime.Composable
import eu.opencloud.android.next.core.sync.FolderIconColor

@Composable
@Suppress("LongParameterList")
fun FolderShortcutPicker(
    color: FolderIconColor,
    image: Bitmap?,
    busy: Boolean,
    onColor: (FolderIconColor) -> Unit,
    onImage: () -> Unit,
    onPin: () -> Unit,
    onDismiss: () -> Unit,
) = eu.opencloud.android.next.core.ui
    .FolderShortcutPicker(color, image, busy, onColor, onImage, onPin, onDismiss)
