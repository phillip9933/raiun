package eu.opencloud.android.next.feature.files

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import eu.opencloud.android.next.core.datastore.PhotoMetadataPreferences
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.isPhotoMetadataSource

@Composable
internal fun rememberOriginalMediaPermission(
    onCancel: () -> Unit = {},
    onReady: (List<Uri>) -> Unit,
): (List<Uri>) -> Unit {
    val context = LocalContext.current
    val preferences = remember(context) { PhotoMetadataPreferences(context) }
    val ready by rememberUpdatedState(onReady)
    val cancelled by rememberUpdatedState(onCancel)
    var pending by rememberSaveable { mutableStateOf<ArrayList<Uri>?>(null) }
    var requesting by rememberSaveable { mutableStateOf(false) }
    var denied by rememberSaveable { mutableStateOf(false) }
    val settingsLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            requesting = false
            if (context.checkSelfPermission(Manifest.permission.ACCESS_MEDIA_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
            ) {
                pending?.let { files ->
                    pending = null
                    ready(files)
                }
            }
        }
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
            requesting = false
            denied = !granted
            if (granted) {
                pending?.let { files ->
                    pending = null
                    ready(files)
                }
            }
        }
    if (pending != null && !requesting) {
        PhotoMetadataPermissionDialog(
            denied = denied,
            onCancel = {
                pending = null
                cancelled()
            },
            onAllow = {
                requesting = true
                if (denied) {
                    settingsLauncher.launch(
                        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                            .setData(Uri.fromParts("package", context.packageName, null)),
                    )
                } else {
                    launcher.launch(Manifest.permission.ACCESS_MEDIA_LOCATION)
                }
            },
            onWithoutMetadata = { neverAskAgain ->
                preferences.askForLocationPermission = !neverAskAgain
                pending?.let { files ->
                    pending = null
                    ready(files)
                }
            },
        )
    }

    return { files ->
        val permissionMissing =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
                context.checkSelfPermission(Manifest.permission.ACCESS_MEDIA_LOCATION) !=
                PackageManager.PERMISSION_GRANTED
        if (preferences.askForLocationPermission &&
            permissionMissing &&
            files.any { isPhotoMetadataSource(context, it) }
        ) {
            denied = false
            pending = ArrayList(files)
        } else {
            ready(files)
        }
    }
}

@Composable
fun PhotoMetadataPermissionDialog(
    denied: Boolean,
    onCancel: () -> Unit,
    onAllow: () -> Unit,
    onWithoutMetadata: (neverAskAgain: Boolean) -> Unit,
) = AlertDialog(
    onDismissRequest = onCancel,
    title = { Text(stringResource(R.string.media_metadata_title)) },
    text = { Text(stringResource(R.string.media_metadata_explanation)) },
    confirmButton = {
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            FilledTonalButton(onClick = onAllow, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(if (denied) R.string.media_metadata_settings else R.string.media_metadata_allow))
            }
            FilledTonalButton(onClick = { onWithoutMetadata(false) }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.media_metadata_continue), textAlign = TextAlign.Center)
            }
            FilledTonalButton(onClick = { onWithoutMetadata(true) }, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.media_metadata_never_ask), textAlign = TextAlign.Center)
            }
            Text(
                stringResource(R.string.media_metadata_settings_note),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    },
)
