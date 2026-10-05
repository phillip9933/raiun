package eu.opencloud.android.next.feature.spaces

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.core.net.toUri
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.VaultLocation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import java.util.Locale

data class SpacesUiState(
    val spaces: List<SpaceEntity> = emptyList(),
    val encryptedSpaces: List<VaultLocation> = emptyList(),
    val loading: Boolean = true,
    val encryptedLoading: Boolean = false,
    val encryptedError: Boolean = false,
    val error: String? = null,
    val busy: Boolean = false,
    val browsableIds: Set<String>? = null,
)

@Composable
// UI boundary maps launch and network failures; cancellation is rethrown.
@Suppress("TooGenericExceptionCaught", "LongParameterList")
fun SpacesRoute(
    accountId: String,
    onOpenSpace: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SpacesViewModel = viewModel(key = "spaces-$accountId"),
    onOpenTrash: (String) -> Unit = {},
    onOpenEncryptedLocation: (VaultLocation) -> Unit = {},
    onEncryptedLocationActions: (VaultLocation) -> Unit = {},
    refreshToken: Int = 0,
) {
    val state by viewModel.state.collectAsState()
    LaunchedEffect(accountId, refreshToken) { viewModel.load(accountId) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var selected by remember(accountId) { mutableStateOf<Pair<SpaceEntity, SpaceAction>?>(null) }
    SpacesScreen(
        state = state,
        onOpenSpace = onOpenSpace,
        onOpenEncryptedLocation = onOpenEncryptedLocation,
        onEncryptedLocationActions = onEncryptedLocationActions,
        modifier = modifier,
        onRefresh = { viewModel.refresh() },
        onAction = { space, action ->
            when (action) {
                SpaceAction.OPEN -> onOpenSpace(space.driveId)
                SpaceAction.TRASH -> onOpenTrash(space.driveId)
                else -> selected = space to action
            }
        },
    )
    selected?.let { (space, action) ->
        if (action == SpaceAction.MEMBERS) {
            SpaceMembersDialog(space) { selected = null }
        } else if (action == SpaceAction.DOWNLOAD) {
            eu.opencloud.android.next.core.ui.FolderDownloadDialog(space.name, { selected = null }) { progress ->
                eu.opencloud.android.next.core.sync
                    .FolderDownloads(context)
                    .space(accountId, space.driveId, progress)
            }
        } else {
            SpaceActionDialog(space, action, onDismiss = { selected = null }, onSubmit = { value ->
                selected = null
                if (action == SpaceAction.WEB) {
                    scope.launch {
                        try {
                            val url = viewModel.webUrl(space)
                            context.startActivity(Intent(Intent.ACTION_VIEW, url.toUri()))
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (failure: Exception) {
                            viewModel.reportError(failure.toOpenCloudError().safeMessage(context))
                        }
                    }
                } else {
                    viewModel.perform(space, action, value)
                }
            })
        }
    }
    state.error?.let { error ->
        AlertDialog(
            onDismissRequest = viewModel::dismissError,
            title = { Text(stringResource(R.string.spaces_operation_failed)) },
            text = { Text(error) },
            confirmButton = {
                TextButton(onClick = viewModel::dismissError) { Text(stringResource(R.string.spaces_close)) }
            },
        )
    }
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
@Suppress("LongParameterList", "CyclomaticComplexMethod") // Explicit callbacks and plain/locked loading variants.
fun SpacesScreen(
    state: SpacesUiState,
    onOpenSpace: (String) -> Unit,
    modifier: Modifier = Modifier,
    onRefresh: () -> Unit = {},
    onAction: (SpaceEntity, SpaceAction) -> Unit = { _, _ -> },
    onOpenEncryptedLocation: (VaultLocation) -> Unit = {},
    onEncryptedLocationActions: (VaultLocation) -> Unit = {},
) {
    val entries = mergedSpaceEntries(state.spaces, state.encryptedSpaces)
    Column(modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingMd),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                stringResource(R.string.spaces_heading),
                Modifier.weight(1f),
                style = MaterialTheme.typography.titleMedium,
            )
            IconButton(onClick = onRefresh, enabled = !state.loading && !state.busy) {
                Icon(Icons.Default.Refresh, stringResource(R.string.spaces_refresh))
            }
        }
        if (state.encryptedError) {
            Text(
                stringResource(R.string.spaces_encrypted_load_failed),
                Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }
        PullToRefreshBox(
            isRefreshing = state.loading || state.encryptedLoading,
            onRefresh = onRefresh,
            modifier = Modifier.weight(1f),
        ) {
            if (state.busy) LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            when {
                (state.loading || state.encryptedLoading) && entries.isEmpty() ->
                    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator()
                    }
                entries.isEmpty() ->
                    LazyColumn(Modifier.fillMaxSize()) {
                        item {
                            SpacesMessage(
                                stringResource(R.string.spaces_none_available),
                                Modifier.fillParentMaxSize(),
                            )
                        }
                    }
                else ->
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(OpenCloudDimensions.SpacingMd),
                        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
                    ) {
                        items(entries, key = { it.key }) { entry ->
                            when (entry) {
                                is SpaceListEntry.Plain ->
                                    SpaceCard(
                                        space = entry.space,
                                        busy = state.busy || state.loading,
                                        browsable = state.browsableIds?.contains(entry.space.driveId) != false,
                                        onOpen = { onOpenSpace(entry.space.driveId) },
                                        onAction = { onAction(entry.space, it) },
                                    )
                                is SpaceListEntry.Encrypted ->
                                    EncryptedSpaceCard(
                                        location = entry.location,
                                        enabled = !state.busy && !state.loading && !state.encryptedLoading,
                                        onOpen = { onOpenEncryptedLocation(entry.location) },
                                        onActions = { onEncryptedLocationActions(entry.location) },
                                    )
                            }
                        }
                    }
            }
        }
    }
}

internal sealed interface SpaceListEntry {
    val title: String
    val key: String

    data class Plain(
        val space: SpaceEntity,
    ) : SpaceListEntry {
        override val title: String = space.name
        override val key: String = "plain:${space.driveId}"
    }

    data class Encrypted(
        val location: VaultLocation,
    ) : SpaceListEntry {
        override val title: String = location.title
        override val key: String = "encrypted:${location.driveId}"
    }
}

internal fun mergedSpaceEntries(
    spaces: List<SpaceEntity>,
    encryptedSpaces: List<VaultLocation>,
): List<SpaceListEntry> {
    val encryptedDriveIds = encryptedSpaces.mapTo(mutableSetOf()) { it.driveId }
    val plainEntries = spaces.filterNot { it.driveId in encryptedDriveIds }.map { SpaceListEntry.Plain(it) }
    val encryptedEntries = encryptedSpaces.map { SpaceListEntry.Encrypted(it) }
    return (plainEntries + encryptedEntries)
        .sortedWith(compareBy(String.CASE_INSENSITIVE_ORDER, SpaceListEntry::title).thenBy { it.key })
}

@Composable
private fun EncryptedSpaceCard(
    location: VaultLocation,
    enabled: Boolean,
    onOpen: () -> Unit,
    onActions: () -> Unit,
) {
    val description =
        if (location.isDisabled) {
            stringResource(R.string.spaces_manage_disabled_encrypted, location.title)
        } else {
            stringResource(R.string.spaces_unlock_encrypted, location.title)
        }
    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .semantics { contentDescription = description }
                .clickable(enabled = enabled && !location.isDisabled, onClick = onOpen),
    ) {
        ListItem(
            headlineContent = { Text(location.title) },
            supportingContent = {
                Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
                    if (location.isDisabled) Text(stringResource(R.string.spaces_disabled_encrypted))
                    Text(stringResource(R.string.spaces_encrypted_summary))
                }
            },
            leadingContent = { Icon(Icons.Default.Lock, contentDescription = null) },
            trailingContent = {
                IconButton(onClick = onActions, enabled = enabled) {
                    Icon(Icons.Default.MoreVert, stringResource(R.string.spaces_encrypted_actions, location.title))
                }
            },
        )
    }
}

@Composable
private fun SpacesMessage(
    message: String,
    modifier: Modifier = Modifier,
) {
    Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        ) {
            Icon(Icons.Default.Apps, contentDescription = null)
            Text(message, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun SpaceCard(
    space: SpaceEntity,
    onOpen: () -> Unit,
    busy: Boolean,
    browsable: Boolean,
    onAction: (SpaceAction) -> Unit,
) {
    val quota = space.quotaSummary()
    val openSpaceDescription = stringResource(R.string.spaces_open_space, space.name)
    Card(
        modifier =
            Modifier
                .fillMaxWidth()
                .semantics { contentDescription = openSpaceDescription }
                .clickable(enabled = !space.isDisabled && !busy && browsable, onClick = onOpen),
    ) {
        ListItem(
            headlineContent = { Text(space.name) },
            supportingContent = {
                Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
                    if (space.isDisabled) Text(stringResource(R.string.spaces_disabled))
                    space.description?.takeIf(String::isNotBlank)?.let { Text(it) }
                    space.ownerName?.takeIf(String::isNotBlank)?.let {
                        Text(stringResource(R.string.spaces_owner, it))
                    }
                    quota?.let { summary ->
                        Text(
                            stringResource(R.string.spaces_quota_summary, summary.used, summary.remaining),
                            style = MaterialTheme.typography.bodySmall,
                        )
                        LinearProgressIndicator(
                            progress = { summary.progress },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }
                }
            },
            leadingContent = { Icon(Icons.Default.Apps, contentDescription = null) },
            trailingContent = { SpaceActionsMenu(space, busy, browsable, onAction) },
        )
    }
}

internal data class QuotaSummary(
    val used: String,
    val remaining: String,
    val progress: Float,
)

internal fun SpaceEntity.quotaSummary(): QuotaSummary? {
    val used = quotaUsedBytes ?: -1
    val total = quotaBytes ?: quotaRemainingBytes?.let { used + it } ?: -1
    if (used < 0 || total <= 0) return null
    val remaining = quotaRemainingBytes ?: (total - used).coerceAtLeast(0)
    return QuotaSummary(
        used = used.toReadableSize(),
        remaining = remaining.toReadableSize(),
        progress = used.toFloat().div(total.toFloat()).coerceIn(0f, 1f),
    )
}

private fun Long.toReadableSize(): String {
    val units = listOf("B", "KB", "MB", "GB", "TB")
    var value = toDouble()
    var unit = 0
    while (value >= 1024 && unit < units.lastIndex) {
        value /= 1024
        unit++
    }
    return if (unit == 0) {
        "$this ${units[unit]}"
    } else {
        String.format(Locale.US, "%.1f %s", value, units[unit])
    }
}
