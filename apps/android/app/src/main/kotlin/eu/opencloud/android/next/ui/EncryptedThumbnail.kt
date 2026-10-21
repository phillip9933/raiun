package eu.opencloud.android.next.ui

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.testTag
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/** Decrypted image data never enters an image-loader cache or a file provider. */
@Composable
internal fun EncryptedThumbnail(
    entry: VaultRouteEntry,
    revision: Long,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    load: suspend (String) -> ByteArray?,
) {
    val loader by rememberUpdatedState(load)
    val entryId = entry.id
    val shouldLoad = enabled && !entry.isFolder
    val owner = remember(entry, revision, enabled) { OwnedBitmap() }
    DisposableEffect(owner) { onDispose { owner.close() } }
    var bitmap by remember(owner) { mutableStateOf<Bitmap?>(null) }
    LaunchedEffect(owner, entryId, shouldLoad) {
        if (!shouldLoad) return@LaunchedEffect
        val bytes = loader(entryId) ?: return@LaunchedEffect
        var decoded: Bitmap? = null
        try {
            withContext(Dispatchers.Default) { decoded = decodeBoundedBitmap(bytes, maximumDimension = 256) }
            currentCoroutineContext().ensureActive()
            val ready = decoded
            if (ready != null && owner.adopt(ready)) {
                decoded = null
                bitmap = ready
            }
        } finally {
            decoded?.recycle()
            bytes.fill(0)
        }
    }
    Box(modifier, contentAlignment = Alignment.Center) {
        val image = bitmap
        if (image != null) {
            Image(
                image.asImageBitmap(),
                null,
                Modifier.matchParentSize().testTag("vault-thumbnail-${entry.id}"),
                contentScale = ContentScale.Crop,
            )
        } else {
            Icon(
                if (entry.isFolder) Icons.Default.Folder else Icons.Default.InsertDriveFile,
                null,
                Modifier.size(OpenCloudDimensions.TouchTarget),
            )
        }
    }
}
