package eu.opencloud.android.next.ui

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Secure preview state and independent reader/editor actions.
internal fun VaultPreviewDialog(
    preview: VaultRoutePreview,
    saving: Boolean,
    saveError: VaultRouteError?,
    onSaveText: (VaultRoutePreview, ByteArray) -> Unit,
    onSaveRange: (VaultRoutePreview, Long, Long, ByteArray) -> Unit,
    onOpenWith: () -> Unit,
    onDismiss: () -> Unit,
) {
    if (preview.kind == VaultPreviewKind.TEXT) {
        if (preview.backing != null) {
            EncryptedPagedTextPreview(preview, saving, saveError, onSaveRange, onDismiss, onOpenWith)
        } else {
            EncryptedTextPreviewDialog(preview, saving, saveError, onSaveText, onDismiss, onOpenWith)
        }
        return
    }
    BackHandler(onBack = onDismiss)
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn, usePlatformDefaultWidth = false),
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = { Text(preview.title, maxLines = 1) },
                    actions = {
                        TextButton(onClick = onOpenWith) { Text(stringResource(R.string.vault_open_with)) }
                    },
                    navigationIcon = {
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.vault_close))
                        }
                    },
                )
            },
        ) { padding ->
            Box(
                Modifier.fillMaxSize().padding(padding).padding(OpenCloudDimensions.SpacingMd),
                contentAlignment = Alignment.Center,
            ) {
                when (preview.kind) {
                    VaultPreviewKind.IMAGE -> {
                        val owner = remember(preview.bytes, preview.backing) { OwnedBitmap() }
                        DisposableEffect(owner) { onDispose { owner.close() } }
                        var decoded by remember(owner) { mutableStateOf(DecodedBitmap(false, null)) }
                        LaunchedEffect(owner) {
                            val copy = preview.bytes.copyOf()
                            var bitmap: Bitmap? = null
                            try {
                                // Cancellation may discard withContext's result on its return dispatch.
                                withContext(Dispatchers.IO) {
                                    bitmap = preview.backing?.let(::decodeBoundedBitmap) ?: decodeBoundedBitmap(copy)
                                }
                                currentCoroutineContext().ensureActive()
                                val ready = bitmap
                                if (ready != null && !owner.adopt(ready)) return@LaunchedEffect
                                bitmap = null
                                decoded = DecodedBitmap(true, ready)
                            } finally {
                                bitmap?.recycle()
                                copy.fill(0)
                            }
                        }
                        if (!decoded.complete) {
                            CircularProgressIndicator()
                        } else if (decoded.bitmap == null) {
                            Text(stringResource(R.string.vault_preview_unavailable))
                        } else {
                            VaultPreviewImage(requireNotNull(decoded.bitmap), preview.title)
                        }
                    }
                    VaultPreviewKind.PDF -> EncryptedPdfPreview(preview.bytes, encryptedBacking = preview.backing)
                    else -> Text(stringResource(R.string.vault_preview_unavailable))
                }
            }
        }
    }
}

@Composable
private fun VaultPreviewImage(
    bitmap: Bitmap,
    title: String,
) {
    var scale by remember(bitmap) { mutableFloatStateOf(1f) }
    var offset by remember(bitmap) { mutableStateOf(Offset.Zero) }
    val transform =
        rememberTransformableState { zoom, pan, _ ->
            scale = (scale * zoom).coerceIn(1f, 5f)
            offset = if (scale == 1f) Offset.Zero else offset + pan
        }
    Box(Modifier.fillMaxSize().clipToBounds().transformable(transform), contentAlignment = Alignment.Center) {
        Image(
            bitmap.asImageBitmap(),
            title,
            Modifier.fillMaxSize().graphicsLayer {
                scaleX = scale
                scaleY = scale
                translationX = offset.x
                translationY = offset.y
            },
        )
    }
}

internal fun decodeBoundedBitmap(
    backing: EncryptedPreviewBacking,
    maximumDimension: Int = MAX_IMAGE_DIMENSION,
): Bitmap? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    backing.inputStream().use { BitmapFactory.decodeStream(it, null, bounds) }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
    var sample = 1
    while (bounds.outWidth / sample > maximumDimension ||
        bounds.outHeight / sample > maximumDimension ||
        bounds.outWidth.toLong() * bounds.outHeight / (sample.toLong() * sample) > MAX_DECODED_PIXELS
    ) {
        sample *= 2
    }
    return backing.inputStream().use { input ->
        BitmapFactory.decodeStream(
            input,
            null,
            BitmapFactory.Options().apply {
                inSampleSize = sample
                inPreferredConfig = Bitmap.Config.ARGB_8888
            },
        )
    }
}

internal fun decodeBoundedBitmap(
    bytes: ByteArray,
    maximumDimension: Int = MAX_IMAGE_DIMENSION,
): Bitmap? {
    var bitmap: Bitmap? = null
    if (bytes.size <= MAX_IMAGE_PREVIEW_BYTES) {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth > 0 &&
            bounds.outHeight > 0 &&
            bounds.outWidth.toLong() * bounds.outHeight <= MAX_IMAGE_PIXELS
        ) {
            var sample = 1
            while (bounds.outWidth / sample > maximumDimension ||
                bounds.outHeight / sample > maximumDimension ||
                bounds.outWidth.toLong() * bounds.outHeight / (sample.toLong() * sample) > MAX_DECODED_PIXELS
            ) {
                sample *= 2
            }
            bitmap =
                BitmapFactory.decodeByteArray(
                    bytes,
                    0,
                    bytes.size,
                    BitmapFactory.Options().apply {
                        inSampleSize = sample
                        inPreferredConfig = Bitmap.Config.ARGB_8888
                    },
                )
        }
    }
    return bitmap
}

private const val MAX_IMAGE_PREVIEW_BYTES = 8 * 1024 * 1024
private const val MAX_IMAGE_PIXELS = 100_000_000L
private const val MAX_DECODED_PIXELS = 4_194_304L
private const val MAX_IMAGE_DIMENSION = 2048

internal data class DecodedBitmap(
    val complete: Boolean,
    val bitmap: Bitmap?,
)

/** Transfers decoded bitmap ownership to the dialog before publishing it to Compose. */
internal class OwnedBitmap {
    private var bitmap: Bitmap? = null
    private var closed = false

    fun adopt(value: Bitmap): Boolean {
        if (closed) return false
        check(bitmap == null)
        bitmap = value
        return true
    }

    fun close() {
        closed = true
        bitmap?.recycle()
        bitmap = null
    }
}
