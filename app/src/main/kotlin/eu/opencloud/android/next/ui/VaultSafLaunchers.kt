package eu.opencloud.android.next.ui

import android.content.ActivityNotFoundException
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue

/** System pickers never receive the vault key or its decrypted source path/name. */
@Composable
internal fun rememberVaultSafLaunchers(viewModel: VaultViewModel): VaultSafLaunchers {
    // Retain the actual request owner, not whichever account's model is composed on result delivery.
    var uploadOwner by remember { mutableStateOf<VaultViewModel?>(null) }
    var exportOwner by remember { mutableStateOf<VaultViewModel?>(null) }
    val upload =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            val owner = uploadOwner
            uploadOwner = null
            owner?.acceptUploadUri(uri)
        }
    val export =
        rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            val owner = exportOwner
            exportOwner = null
            owner?.acceptExportUri(uri)
        }
    DisposableEffect(viewModel) {
        onDispose {
            if (uploadOwner === viewModel) {
                uploadOwner = null
                viewModel.acceptUploadUri(null)
            }
            if (exportOwner === viewModel) {
                exportOwner = null
                viewModel.acceptExportUri(null)
            }
        }
    }
    return VaultSafLaunchers(
        upload = {
            viewModel.prepareUpload {
                uploadOwner = viewModel
                try {
                    upload.launch(arrayOf("*/*"))
                } catch (_: ActivityNotFoundException) {
                    uploadOwner = null
                    viewModel.acceptUploadUri(null)
                }
            }
        },
        export = { id ->
            viewModel.prepareExport(id) {
                exportOwner = viewModel
                try {
                    export.launch("decrypted-file")
                } catch (_: ActivityNotFoundException) {
                    exportOwner = null
                    viewModel.acceptExportUri(null)
                }
            }
        },
    )
}

internal data class VaultSafLaunchers(
    val upload: () -> Unit,
    val export: (String) -> Unit,
)
