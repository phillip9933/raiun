package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.AccountCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Workspaces
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScannerDestinationScreen(
    state: ScannerDestinationPickerState,
    actions: ScannerDestinationActions,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.scanner_destination_title)) },
                navigationIcon = {
                    IconButton(onClick = actions.dismiss) {
                        Icon(Icons.Default.Close, stringResource(R.string.scanner_destination_cancel))
                    }
                },
            )
        },
        bottomBar = {
            Surface(tonalElevation = OpenCloudDimensions.SpacingXs) {
                Button(
                    onClick = actions.choose,
                    enabled = !state.busy && state.validFolder && state.spaceId != null,
                    modifier = Modifier.fillMaxWidth().navigationBarsPadding().padding(OpenCloudDimensions.SpacingMd),
                ) { Text(stringResource(R.string.scanner_destination_choose)) }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).padding(horizontal = OpenCloudDimensions.SpacingMd)) {
            DestinationHeading(state, actions.spaces)
            if (state.spaceId != null) DestinationBreadcrumbs(state, actions)
            state.error?.let { message ->
                Text(message, color = MaterialTheme.colorScheme.error)
                TextButton(onClick = actions.retry) { Text(stringResource(R.string.scanner_destination_retry)) }
            }
            if (state.busy) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
            } else {
                DestinationRows(state, actions, Modifier.weight(1f))
            }
        }
    }
}

@Composable
private fun DestinationHeading(
    state: ScannerDestinationPickerState,
    onChange: () -> Unit,
) {
    val space = state.spaces.firstOrNull { it.driveId == state.spaceId }
    Card(Modifier.fillMaxWidth().padding(bottom = OpenCloudDimensions.SpacingSm)) {
        Column(Modifier.padding(OpenCloudDimensions.SpacingMd)) {
            Text(state.accountLabel, style = MaterialTheme.typography.labelMedium)
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(
                        space?.let { destinationSpaceName(it) }
                            ?: stringResource(R.string.scanner_destination_locations),
                        style = MaterialTheme.typography.titleMedium,
                    )
                    if (space != null) {
                        Text(
                            state.path.takeUnless { it == "/" }
                                ?: stringResource(R.string.scanner_destination_root_folder),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
                if (space != null) {
                    OutlinedButton(onClick = onChange, enabled = !state.busy) {
                        Text(stringResource(R.string.scanner_destination_change))
                    }
                }
            }
        }
    }
}

@Composable
private fun DestinationBreadcrumbs(
    state: ScannerDestinationPickerState,
    actions: ScannerDestinationActions,
) {
    val space = state.spaces.firstOrNull { it.driveId == state.spaceId } ?: return
    Row(
        Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        FilterChip(
            selected = state.trail.isEmpty(),
            onClick = { actions.space(space.driveId) },
            enabled = !state.busy,
            label = { Text(destinationSpaceName(space)) },
        )
        state.trail.forEachIndexed { index, folder ->
            Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null)
            FilterChip(
                selected = index == state.trail.lastIndex,
                onClick = { actions.breadcrumb(index) },
                enabled = !state.busy,
                label = { Text(folder.name) },
            )
        }
    }
}

@Composable
private fun DestinationRows(
    state: ScannerDestinationPickerState,
    actions: ScannerDestinationActions,
    modifier: Modifier = Modifier,
) {
    LazyColumn(modifier) {
        if (state.spaceId == null) {
            items(state.spaces, key = { it.driveId }) { space ->
                ListItem(
                    headlineContent = { Text(destinationSpaceName(space)) },
                    supportingContent = {
                        Text(
                            stringResource(
                                if (space.type ==
                                    "personal"
                                ) {
                                    R.string.scanner_destination_personal
                                } else {
                                    R.string.scanner_destination_project
                                },
                            ),
                        )
                    },
                    leadingContent = {
                        Icon(
                            if (space.type ==
                                "personal"
                            ) {
                                Icons.Default.AccountCircle
                            } else {
                                Icons.Default.Workspaces
                            },
                            null,
                        )
                    },
                    trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                    modifier = Modifier.clickable(role = Role.Button) { actions.space(space.driveId) },
                )
                HorizontalDivider()
            }
        } else {
            if (state.trail.isNotEmpty()) {
                item {
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.scanner_destination_up)) },
                        leadingContent = { Icon(Icons.AutoMirrored.Filled.ArrowBack, null) },
                        modifier = Modifier.clickable(role = Role.Button, onClick = actions.up),
                    )
                    HorizontalDivider()
                }
            }
            items(state.folders, key = { it.remoteId }) { folder ->
                ListItem(
                    headlineContent = { Text(folder.name) },
                    leadingContent = { Icon(Icons.Default.Folder, null) },
                    trailingContent = { Icon(Icons.AutoMirrored.Filled.KeyboardArrowRight, null) },
                    modifier = Modifier.clickable(role = Role.Button) { actions.folder(folder) },
                )
                HorizontalDivider()
            }
            if (state.folders.isEmpty() && state.validFolder) {
                item {
                    Text(
                        stringResource(R.string.scanner_destination_empty),
                        modifier = Modifier.padding(vertical = OpenCloudDimensions.SpacingMd),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
            }
        }
    }
}

@Composable
private fun destinationSpaceName(space: SpaceEntity): String =
    if (space.type == "personal") stringResource(R.string.browser_personal) else space.name
