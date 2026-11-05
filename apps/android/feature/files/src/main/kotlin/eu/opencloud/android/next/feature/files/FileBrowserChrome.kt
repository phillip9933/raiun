package eu.opencloud.android.next.feature.files

import android.content.Intent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Forum
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.OfflinePin
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.typedState
import eu.opencloud.android.next.core.datastore.NavigationItem
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.component.HorizontalDivider
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.ui.BrowserToolbar

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList")
internal fun BrowserTopAppBar(
    accountId: String,
    query: String,
    onQueryChange: (String) -> Unit,
    onOpenDrawer: () -> Unit,
    onOpenAccount: () -> Unit,
    notifications: @Composable () -> Unit,
) = TopAppBar(
    title = {
        TextField(
            value = query,
            onValueChange = onQueryChange,
            modifier =
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = OpenCloudDimensions.SpacingXxs)
                    .browserDescription(R.string.browser_filter_files),
            placeholder = { Text(stringResource(R.string.browser_search_in_files)) },
            leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
            trailingIcon = {
                if (query.isNotEmpty()) {
                    IconButton(onClick = { onQueryChange("") }) {
                        Icon(Icons.Default.Close, contentDescription = stringResource(R.string.browser_clear_search))
                    }
                }
            },
            singleLine = true,
            shape = RoundedCornerShape(50),
        )
    },
    navigationIcon = {
        IconButton(
            onClick = onOpenDrawer,
            modifier = Modifier.size(OpenCloudDimensions.TouchTarget),
        ) {
            Icon(Icons.Default.Menu, contentDescription = stringResource(R.string.browser_open_navigation_drawer))
        }
    },
    actions = {
        notifications()
        AccountAvatar(accountId, onOpenAccount)
    },
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun DestinationTopAppBar(
    title: String,
    accountId: String,
    onOpenDrawer: () -> Unit,
    onOpenAccount: () -> Unit,
    notifications: @Composable () -> Unit,
) = TopAppBar(
    title = { Text(title) },
    navigationIcon = {
        IconButton(onClick = onOpenDrawer, modifier = Modifier.size(OpenCloudDimensions.TouchTarget)) {
            Icon(Icons.Default.Menu, contentDescription = stringResource(R.string.browser_open_navigation_drawer))
        }
    },
    actions = {
        notifications()
        AccountAvatar(accountId, onOpenAccount)
    },
)

@Composable
private fun AccountAvatar(
    accountId: String,
    onOpenAccount: () -> Unit,
) {
    val accountDescription =
        stringResource(R.string.browser_open_account_information) + ", " +
            eu.opencloud.android.next.core.ui
                .accountIdentityDescription(accountId)
    Box(
        modifier = Modifier.padding(end = OpenCloudDimensions.SpacingMd),
        contentAlignment = Alignment.Center,
    ) {
        IconButton(
            onClick = onOpenAccount,
            modifier =
                Modifier
                    .size(OpenCloudDimensions.TouchTarget)
                    .semantics { contentDescription = accountDescription },
        ) {
            Surface(
                modifier = Modifier.size(OpenCloudDimensions.AvatarSize),
                shape = CircleShape,
                color = MaterialTheme.colorScheme.primaryContainer,
            ) {
                Box(contentAlignment = Alignment.Center) {
                    eu.opencloud.android.next.core.ui
                        .ProfileAvatar(accountId)
                }
            }
        }
    }
}

@Composable
@Suppress("LongParameterList")
internal fun BrowserSubHeader(
    canNavigateUp: Boolean,
    layout: BrowserLayout,
    sortCriterion: BrowserSortCriterion,
    sortAscending: Boolean,
    showSortMenu: Boolean,
    onNavigateUp: () -> Unit,
    onShowSortMenu: () -> Unit,
    onDismissSortMenu: () -> Unit,
    onSortSelect: (BrowserSortCriterion) -> Unit,
    onToggleLayout: () -> Unit,
) {
    BrowserToolbar(
        canNavigateUp,
        SettingsBrowserLayout.valueOf(layout.name),
        onNavigateUp,
        onToggleLayout,
    ) {
        Box {
            TextButton(onClick = onShowSortMenu) {
                Text(stringResource(sortCriterion.labelResource))
                Icon(
                    imageVector =
                        if (sortAscending) {
                            Icons.Default.ArrowUpward
                        } else {
                            Icons.Default.ArrowDownward
                        },
                    contentDescription =
                        stringResource(
                            if (sortAscending) R.string.browser_ascending else R.string.browser_descending,
                        ),
                )
            }
            DropdownMenu(expanded = showSortMenu, onDismissRequest = onDismissSortMenu) {
                BrowserSortCriterion.entries.forEach { criterion ->
                    DropdownMenuItem(
                        text = { Text(stringResource(criterion.labelResource)) },
                        trailingIcon = {
                            if (criterion == sortCriterion) {
                                Icon(
                                    Icons.Default.Check,
                                    contentDescription = stringResource(R.string.browser_selected),
                                )
                            }
                        },
                        onClick = { onSortSelect(criterion) },
                    )
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun SelectionTopAppBar(
    accountId: String,
    selectedCount: Int,
    onClearSelection: () -> Unit,
    onDownloadSelection: () -> Unit,
) {
    val accountDescription =
        eu.opencloud.android.next.core.ui
            .accountIdentityDescription(accountId)
    TopAppBar(
        modifier = Modifier.semantics { contentDescription = accountDescription },
        title = { Text(pluralStringResource(R.plurals.browser_selected_count, selectedCount, selectedCount)) },
        navigationIcon = {
            IconButton(onClick = onClearSelection) {
                Icon(Icons.Default.Close, contentDescription = stringResource(R.string.browser_clear_selection))
            }
        },
        actions = {
            SelectionAction(
                stringResource(R.string.browser_keep_offline),
                Icons.Default.OfflinePin,
                stringResource(R.string.browser_download_selected_offline),
                onDownloadSelection,
            )
        },
    )
}

@Composable
internal fun TransferSummary(
    transfers: List<TransferEntity>,
    onOpenTransfers: () -> Unit,
) {
    val active = browserTransferRepresentative(transfers) ?: return
    val progress =
        if (active.bytesTotal > 0) {
            (active.bytesTransferred.toFloat() / active.bytesTotal).coerceIn(0f, 1f)
        } else {
            0f
        }
    Column(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(onClickLabel = stringResource(R.string.browser_open_transfers), onClick = onOpenTransfers)
                .padding(horizontal = OpenCloudDimensions.SpacingMd),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs),
    ) {
        Text(
            text = browserTransferSummary(active),
            color =
                if (active.typedState.requiresAttention) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            style = MaterialTheme.typography.labelMedium,
        )
        if (active.typedState.isRunnable) {
            if (active.bytesTotal >
                0
            ) {
                LinearProgressIndicator(progress = { progress }, modifier = Modifier.fillMaxWidth())
            } else {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
        }
    }
}

@Composable
internal fun ExportStatus(
    state: FileBrowserUiState,
    onDismiss: () -> Unit,
) {
    state.exportStatus?.let { status ->
        Column(Modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingMd)) {
            Text(status, style = MaterialTheme.typography.bodySmall)
            if (state.exporting) {
                androidx.compose.material3.LinearProgressIndicator(Modifier.fillMaxWidth())
            } else {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_dismiss)) }
            }
        }
    }
}

@Composable
@Suppress("LongParameterList")
internal fun BrowserNavigationDrawer(
    releaseVersion: String,
    selectedDestination: FileBrowserDestination,
    pinnedItems: List<NavigationItem>,
    onNavigate: (NavigationItem) -> Unit,
    onDeletedFiles: () -> Unit,
    onSettings: () -> Unit,
    onAppUpdates: () -> Unit,
    personalSpace: eu.opencloud.android.next.core.database.SpaceEntity?,
    onVaults: (() -> Unit)? = null,
) = ModalDrawerSheet(
    modifier =
        Modifier.width(
            (androidx.compose.ui.platform.LocalConfiguration.current.screenWidthDp.dp * 0.75f).coerceAtMost(
                OpenCloudDimensions.DrawerMaxWidth,
            ),
        ),
) {
    val context = LocalContext.current
    eu.opencloud.android.next.core.designsystem.RaiunWordmark(
        Modifier.padding(OpenCloudDimensions.SpacingXl),
    )
    HorizontalDivider()
    NavigationItem.entries.filterNot { it in pinnedItems }.forEach { item ->
        NavigationDrawerItem(
            label = { Text(stringResource(item.navigationLabel())) },
            selected = item.browserDestination() == selectedDestination,
            onClick = { onNavigate(item) },
            icon = { Icon(item.navigationIcon(), null) },
            modifier =
                Modifier
                    .padding(horizontal = OpenCloudDimensions.SpacingSm)
                    .browserDescription(R.string.browser_navigate_to, stringResource(item.navigationLabel())),
        )
    }
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_deleted_files)) },
        selected = false,
        onClick = onDeletedFiles,
        icon = { Icon(Icons.Default.Delete, contentDescription = null) },
        modifier =
            Modifier
                .padding(horizontal = OpenCloudDimensions.SpacingSm)
                .browserDescription(R.string.browser_navigate_to_deleted_files),
    )
    onVaults?.let { open ->
        VaultNavigationDrawerItem(open)
    }
    Spacer(Modifier.weight(1f))
    HorizontalDivider()
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_settings)) },
        selected = false,
        onClick = onSettings,
        icon = { Icon(Icons.Default.Settings, contentDescription = null) },
        modifier =
            Modifier
                .padding(OpenCloudDimensions.SpacingSm)
                .browserDescription(R.string.browser_open_settings),
    )
    NavigationDrawerItem(label = {
        Text(stringResource(R.string.browser_community_discussions))
    }, selected = false, onClick = {
        context.startActivity(
            Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://github.com/orgs/opencloud-eu/discussions")),
        )
    }, icon = {
        Icon(
            Icons.Default.Forum,
            null,
        )
    }, modifier = Modifier.padding(horizontal = OpenCloudDimensions.SpacingSm))
    personalSpace?.let { space ->
        val used = space.quotaUsedBytes
        val total = space.quotaBytes?.takeIf { it > 0 }
        Column(Modifier.padding(OpenCloudDimensions.SpacingMd)) {
            Text(stringResource(R.string.browser_personal_storage), style = MaterialTheme.typography.labelLarge)
            Text(
                browserQuotaSummary(used, total),
            )
            if (used != null &&
                total != null
            ) {
                LinearProgressIndicator(
                    progress = { (used.toFloat() / total).coerceIn(0f, 1f) },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
    Text(
        text = stringResource(R.string.browser_version, releaseVersion),
        modifier = Modifier.clickable(onClick = onAppUpdates).padding(OpenCloudDimensions.SpacingXl),
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        style = MaterialTheme.typography.bodySmall,
    )
}

@Composable
private fun VaultNavigationDrawerItem(onOpen: () -> Unit) {
    NavigationDrawerItem(
        label = { Text(stringResource(R.string.browser_vaults)) },
        selected = false,
        onClick = onOpen,
        icon = { Icon(Icons.Default.Lock, contentDescription = null) },
        modifier = Modifier.padding(horizontal = OpenCloudDimensions.SpacingSm),
    )
}

@Composable
internal fun BrowserBottomNavigation(
    selectedDestination: FileBrowserDestination,
    pinnedItems: List<NavigationItem>,
    onNavigate: (NavigationItem) -> Unit,
) = NavigationBar(containerColor = MaterialTheme.colorScheme.surfaceContainer) {
    pinnedItems.forEach { item ->
        NavigationBarItem(
            selected = item.browserDestination() == selectedDestination,
            onClick = { onNavigate(item) },
            icon = { Icon(item.navigationIcon(), null) },
            label = {
                Text(stringResource(item.navigationLabel()), maxLines = 1, style = MaterialTheme.typography.labelSmall)
            },
            modifier =
                Modifier.browserDescription(
                    R.string.browser_navigate_to,
                    stringResource(item.navigationLabel()),
                ),
        )
    }
}

internal fun NavigationItem.browserDestination(): FileBrowserDestination? =
    when (this) {
        NavigationItem.RECENTS -> FileBrowserDestination.Recents
        NavigationItem.FAVORITES -> FileBrowserDestination.Favorites
        NavigationItem.PERSONAL -> FileBrowserDestination.Personal
        NavigationItem.SHARES -> FileBrowserDestination.Shares
        NavigationItem.SPACES -> FileBrowserDestination.Spaces
        NavigationItem.OFFLINE -> FileBrowserDestination.Offline
        NavigationItem.TRANSFERS -> null
    }

@androidx.annotation.StringRes
private fun NavigationItem.navigationLabel(): Int = browserDestination()?.labelResource ?: R.string.browser_uploads

private fun NavigationItem.navigationIcon(): ImageVector = browserDestination()?.icon ?: Icons.Default.CloudSync
