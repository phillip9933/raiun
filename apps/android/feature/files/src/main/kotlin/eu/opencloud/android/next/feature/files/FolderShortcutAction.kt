package eu.opencloud.android.next.feature.files

import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.FolderShortcuts

@Composable
internal fun FolderShortcutAction(resource: ResourceEntity) {
    val context = LocalContext.current
    if (resource.kind == ResourceKind.FOLDER) {
        eu.opencloud.android.next.core.ui
            .FolderShortcutAction { icon -> FolderShortcuts(context).pin(resource, icon) }
    }
}
