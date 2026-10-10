package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.ImagePreviews
import eu.opencloud.android.next.core.sync.isVideoPreview
import kotlinx.coroutines.CancellationException

@Composable
internal fun ResourceThumbnail(
    resource: ResourceEntity,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val previewable =
        resource.kind == ResourceKind.FILE &&
            (resource.isImagePreview() || resource.isVideoPreview())
    val bitmap by produceState<android.graphics.Bitmap?>(
        null,
        resource.accountId,
        resource.spaceId,
        resource.remoteId,
        resource.path,
        resource.kind,
        resource.eTag,
        resource.modifiedAtEpochMillis,
        resource.sizeBytes,
        resource.hasLocalCopy,
        resource.localPath,
        resource.mimeType,
        resource.name,
    ) {
        if (previewable) {
            value =
                try {
                    ImagePreviews.load(context, resource)
                } catch (
                    cancelled: CancellationException,
                ) {
                    throw cancelled
                } catch (_: Exception) {
                    null
                }
        }
    }
    bitmap?.let {
        Image(
            it.asImageBitmap(),
            null,
            modifier.size(OpenCloudDimensions.TouchTarget),
            contentScale = ContentScale.Crop,
        )
    }
        ?: ResourceIcon(resource.kind, modifier)
}

internal fun ResourceEntity.isImagePreview(): Boolean =
    mimeType?.startsWith("image/") == true ||
        name.substringAfterLast('.', "").lowercase() in setOf("jpg", "jpeg", "png", "webp", "heic", "gif")
