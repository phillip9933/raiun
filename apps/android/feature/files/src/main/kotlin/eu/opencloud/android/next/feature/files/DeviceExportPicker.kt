package eu.opencloud.android.next.feature.files

import android.app.Activity
import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.fileMimeType

@Composable
internal fun rememberDeviceExportLauncher(
    accountId: String,
    viewModel: FileBrowserViewModel,
    exporting: Boolean,
): (ResourceEntity, Boolean) -> Unit {
    var pending by rememberSaveable { mutableStateOf(arrayListOf<String>()) }
    var move by rememberSaveable { mutableStateOf(false) }
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val target = result.data?.data?.takeIf { result.resultCode == Activity.RESULT_OK }
            val key = pending
            pending = arrayListOf()
            if (target != null && key.size == 3 && key[0] == accountId) {
                viewModel.exportFile(key[1], key[2], target, move)
            }
        }
    return { resource, removeLocal ->
        if (!exporting && pending.isEmpty()) {
            pending = arrayListOf(resource.accountId, resource.spaceId, resource.remoteId)
            move = removeLocal
            launcher.launch(
                Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = fileMimeType(resource.name, resource.mimeType)
                    putExtra(Intent.EXTRA_TITLE, resource.name)
                },
            )
        }
    }
}
