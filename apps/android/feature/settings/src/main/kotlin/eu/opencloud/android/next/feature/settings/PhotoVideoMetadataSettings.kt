package eu.opencloud.android.next.feature.settings

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.LocationOn
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import eu.opencloud.android.next.core.datastore.PhotoMetadataPreferences
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun MetadataPermissionSettings() {
    val context = LocalContext.current
    var revision by remember { mutableIntStateOf(0) }
    val preferences = remember(context) { PhotoMetadataPreferences(context) }
    var askForLocationPermission by remember { mutableStateOf(preferences.askForLocationPermission) }
    val permissionLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { revision++ }
    val settingsLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { revision++ }
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        askForLocationPermission = preferences.askForLocationPermission
        revision++
    }
    val needed = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
    val granted =
        remember(revision) {
            !needed ||
                context.checkSelfPermission(Manifest.permission.ACCESS_MEDIA_LOCATION) ==
                PackageManager.PERMISSION_GRANTED
        }
    PhotoVideoMetadataSettings(
        permissionStatus =
            when {
                !needed -> PhotoPermissionStatus.NOT_NEEDED
                granted -> PhotoPermissionStatus.ALLOWED
                else -> PhotoPermissionStatus.DENIED
            },
        askForLocationPermission = askForLocationPermission,
        onAskForLocationPermissionChange = {
            preferences.askForLocationPermission = it
            askForLocationPermission = it
        },
        onRequestPermission = {
            preferences.askForLocationPermission = true
            askForLocationPermission = true
            permissionLauncher.launch(Manifest.permission.ACCESS_MEDIA_LOCATION)
        },
        onManagePermissions = {
            settingsLauncher.launch(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.fromParts("package", context.packageName, null)),
            )
        },
    )
}

@Composable
internal fun PhotoVideoMetadataSettings(
    permissionStatus: PhotoPermissionStatus,
    askForLocationPermission: Boolean,
    onAskForLocationPermissionChange: (Boolean) -> Unit,
    onRequestPermission: () -> Unit,
    onManagePermissions: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        ListItem(
            headlineContent = { Text(stringResource(R.string.settings_photo_video_metadata)) },
            supportingContent = {
                Text(
                    when (permissionStatus) {
                        PhotoPermissionStatus.NOT_NEEDED ->
                            stringResource(
                                R.string.settings_photo_video_metadata_not_needed,
                            )
                        PhotoPermissionStatus.ALLOWED -> stringResource(R.string.settings_photo_video_metadata_allowed)
                        PhotoPermissionStatus.DENIED ->
                            stringResource(
                                R.string.settings_photo_video_metadata_not_allowed,
                            )
                    },
                )
            },
            leadingContent = { Icon(Icons.Default.LocationOn, contentDescription = null) },
            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
        )
        Column(Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd)) {
            Text(
                stringResource(R.string.settings_photo_video_metadata_description),
                modifier = Modifier.padding(bottom = OpenCloudDimensions.SpacingXs),
                style = MaterialTheme.typography.bodySmall,
            )
            ListItem(
                headlineContent = { Text(stringResource(R.string.settings_ask_for_photo_location)) },
                supportingContent = {
                    Text(stringResource(R.string.settings_ask_for_photo_location_description))
                },
                trailingContent = {
                    Switch(askForLocationPermission, onCheckedChange = onAskForLocationPermissionChange)
                },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
            if (permissionStatus == PhotoPermissionStatus.DENIED) {
                FilledTonalButton(onClick = onRequestPermission, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.settings_request_photo_video_metadata))
                }
            }
            OutlinedButton(onClick = onManagePermissions, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.settings_manage_app_permissions))
            }
        }
    }
}

internal enum class PhotoPermissionStatus { NOT_NEEDED, ALLOWED, DENIED }
