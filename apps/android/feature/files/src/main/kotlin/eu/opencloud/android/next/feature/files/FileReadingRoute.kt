package eu.opencloud.android.next.feature.files

import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.datastore.previewKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.sync.LocalCopyLease
import eu.opencloud.android.next.core.ui.FilePreviewRoute
import eu.opencloud.android.next.core.ui.copyPreview

@Composable
internal fun FileReadingRoute(
    resource: ResourceEntity,
    prepare: suspend (ResourceEntity) -> ResourceEntity,
    recordOpened: (ResourceEntity) -> Unit,
    onClose: () -> Unit,
    onOpenWith: () -> Unit,
) {
    val context = LocalContext.current
    var editing by rememberSaveable { mutableStateOf(false) }
    var editable by rememberSaveable { mutableStateOf(false) }
    if (editing) {
        TextEditorRoute(resource.accountId, resource.spaceId, resource.remoteId, onClose = { editing = false })
    } else {
        FilePreviewRoute(
            resource.name,
            requireNotNull(previewKind(resource.name, resource.mimeType)),
            onClose,
            onOpenWith,
            load = { destination ->
                val ready = prepare(resource)
                val file =
                    requireNotNull(
                        validatedCachedFile(
                            resourceCacheDirectory(context.filesDir, ready.accountId, ready.spaceId),
                            ready.localPath,
                            ready.sizeBytes,
                        ),
                    )
                LocalCopyLease.read(file) { copyPreview(file.inputStream(), destination) }
                editable = canEditText(ready)
                recordOpened(ready)
            },
            onEdit = if (editable) ({ editing = true }) else null,
        )
    }
}
