package eu.opencloud.android.next.core.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.IntSize
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

/** The exact square output is used by both Personal and shared-folder shortcut creation. */
fun cropFolderIcon(
    source: Bitmap,
    zoom: Float,
    horizontal: Float,
    vertical: Float,
): Bitmap {
    val side = (minOf(source.width, source.height) / zoom.coerceIn(1f, 4f)).toInt().coerceAtLeast(1)
    val left = ((source.width - side) * horizontal.coerceIn(0f, 1f)).toInt()
    val top = ((source.height - side) * vertical.coerceIn(0f, 1f)).toInt()
    return Bitmap.createBitmap(source, left, top, side, side)
}

@Composable
fun FolderIconCropDialog(
    source: Bitmap,
    onCancel: () -> Unit,
    onApply: (Bitmap) -> Unit,
) {
    var crop by remember(source) { mutableStateOf(FolderIconCrop()) }
    var viewport by remember { mutableFloatStateOf(1f) }
    val sourceSize = remember(source) { IntSize(source.width, source.height) }
    val cropped = remember(source, crop) { cropFolderIcon(source, crop.zoom, crop.horizontal, crop.vertical) }
    val zoomIn = stringResource(R.string.folder_crop_zoom_in)
    val zoomOut = stringResource(R.string.folder_crop_zoom_out)
    val reset = stringResource(R.string.folder_crop_reset)
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.folder_crop_title)) },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                Image(
                    cropped.asImageBitmap(),
                    stringResource(R.string.folder_shortcut_preview),
                    Modifier
                        .size(OpenCloudDimensions.TouchTarget * 5)
                        .clip(CircleShape)
                        .onSizeChanged { viewport = it.width.toFloat().coerceAtLeast(1f) }
                        .pointerInput(source) {
                            detectTransformGestures { centroid, pan, zoom, _ ->
                                crop = crop.transformed(sourceSize, viewport, centroid, pan, zoom)
                            }
                        }.semantics {
                            customActions =
                                listOf(
                                    CustomAccessibilityAction(zoomIn) {
                                        crop =
                                            crop.transformed(
                                                sourceSize,
                                                viewport,
                                                Offset(viewport / 2, viewport / 2),
                                                Offset.Zero,
                                                1.25f,
                                            )
                                        true
                                    },
                                    CustomAccessibilityAction(zoomOut) {
                                        crop =
                                            crop.transformed(
                                                sourceSize,
                                                viewport,
                                                Offset(viewport / 2, viewport / 2),
                                                Offset.Zero,
                                                0.8f,
                                            )
                                        true
                                    },
                                    CustomAccessibilityAction(reset) {
                                        crop = FolderIconCrop()
                                        true
                                    },
                                )
                        },
                )
                Text(stringResource(R.string.folder_crop_hint))
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onApply(cropped) },
            ) { Text(stringResource(R.string.folder_crop_use)) }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.folder_shortcut_cancel)) } },
    )
}

/** Gesture coordinates stay anchored beneath the fingers and never expose empty crop borders. */
data class FolderIconCrop(
    val zoom: Float = 1f,
    val horizontal: Float = 0.5f,
    val vertical: Float = 0.5f,
) {
    fun transformed(
        source: IntSize,
        viewport: Float,
        centroid: Offset,
        pan: Offset,
        scale: Float,
    ): FolderIconCrop {
        val nextZoom = (zoom * scale).coerceIn(1f, 4f)
        val oldSide = minOf(source.width, source.height) / zoom
        val side = minOf(source.width, source.height) / nextZoom

        fun position(
            size: Int,
            current: Float,
            anchor: Float,
            movement: Float,
        ): Float {
            val available = size - side
            if (available <= 0f) return 0.5f
            val sourceAnchor = (size - oldSide) * current + anchor / viewport * oldSide
            return ((sourceAnchor - (anchor + movement) / viewport * side) / available).coerceIn(0f, 1f)
        }
        return FolderIconCrop(
            nextZoom,
            position(source.width, horizontal, centroid.x, pan.x),
            position(source.height, vertical, centroid.y, pan.y),
        )
    }
}
