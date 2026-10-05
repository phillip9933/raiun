package eu.opencloud.android.next.feature.shares

import android.app.Application
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.ShareEntity
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.sync.ShareManager
import eu.opencloud.android.next.core.sync.TransientPublicLink
import eu.opencloud.android.next.core.ui.BrowserAction
import eu.opencloud.android.next.core.ui.BrowserActionSheet
import eu.opencloud.android.next.core.ui.BrowserContent
import eu.opencloud.android.next.core.ui.BrowserEntry
import eu.opencloud.android.next.core.ui.BrowserToolbar
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate

enum class ShareCategory(
    val labelRes: Int,
) {
    WITH_ME(R.string.share_category_with_me),
    BY_ME(R.string.share_category_by_me),
    PUBLIC(R.string.share_category_public),
}

data class SharesUiState(
    val account: AccountEntity? = null,
    val shares: List<ShareEntity> = emptyList(),
    val category: ShareCategory = ShareCategory.WITH_ME,
    val resource: ResourceEntity? = null,
    val resourceShares: List<ShareEntity> = emptyList(),
    val recipients: List<ShareRecipient> = emptyList(),
    val loading: Boolean = false,
    val saving: Boolean = false,
    val error: String? = null,
    val message: String? = null,
    val createdPublicLink: TransientPublicLink? = null,
)

class SharesViewModel(
    application: Application,
) : AndroidViewModel(application) {
    internal val controller =
        SharesController(
            viewModelScope,
            AndroidSharesBackend(application),
            errorMessage = { it.safeMessage(application) },
        )
}

@Composable
fun SharesRoute(
    accountId: String,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SharesViewModel = viewModel(key = "shares-$accountId"),
) {
    val state by viewModel.controller.state.collectAsState()
    LaunchedEffect(accountId) { viewModel.controller.load(accountId) }
    SharesScreen(
        state,
        onNavigateBack,
        viewModel.controller::selectCategory,
        viewModel.controller::refresh,
        viewModel.controller::updatePermissions,
        viewModel.controller::revoke,
        viewModel.controller::dismissNotice,
        modifier,
    )
}

@Composable
@Suppress("LongParameterList") // Account navigation, optional shortcut and injected view model.
fun TopLevelSharesRoute(
    accountId: String,
    modifier: Modifier = Modifier,
    initialFolder: eu.opencloud.android.next.core.sync.SharedFolderRequest? = null,
    onConsumeInitialFolder: () -> Unit = {},
    onBrowseResource: ((ResourceEntity) -> Unit)? = null,
    viewModel: SharesViewModel = viewModel(key = "shares-$accountId"),
) {
    val context = LocalContext.current
    val owner = rememberCoroutineScope()
    val settings =
        remember(context) {
            eu.opencloud.android.next.core.datastore.SettingsRepository
                .create(context)
        }
    val preferences by settings.settings.collectAsState(
        initial =
            eu.opencloud.android.next.core.datastore
                .UserSettings(),
    )
    val state by viewModel.controller.state.collectAsState()
    LaunchedEffect(accountId) { viewModel.controller.load(accountId) }
    LaunchedEffect(initialFolder) {
        if (initialFolder != null) viewModel.controller.selectCategory(ShareCategory.WITH_ME)
    }
    SharesContent(
        state = state,
        onCategory = viewModel.controller::selectCategory,
        onRefresh = viewModel.controller::refresh,
        onUpdatePermissions = viewModel.controller::updatePermissions,
        onRevoke = viewModel.controller::revoke,
        onDismissNotice = viewModel.controller::dismissNotice,
        modifier = modifier,
        onBrowseResource = onBrowseResource,
        layout = preferences.browserLayout,
        onLayout = { value -> owner.launch { settings.setBrowserLayout(value) } },
        incomingContent = { IncomingBrowserRoute(accountId, initialFolder, onConsumeInitialFolder) },
    )
}

@Composable
fun ResourceSharesRoute(
    accountId: String,
    resource: ResourceEntity,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SharesViewModel = viewModel(key = "resource-shares-$accountId-${resource.remoteId}"),
) {
    val state by viewModel.controller.state.collectAsState()
    LaunchedEffect(accountId, resource.remoteId) { viewModel.controller.load(accountId, resource) }
    ResourceSharesScreen(
        state,
        onNavigateBack,
        viewModel.controller::searchRecipients,
        viewModel.controller::createRecipientShare,
        viewModel.controller::createPublicLink,
        viewModel.controller::updatePermissions,
        viewModel.controller::revoke,
        viewModel.controller::dismissNotice,
        modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList")
fun SharesScreen(
    state: SharesUiState,
    onNavigateBack: () -> Unit,
    onCategory: (ShareCategory) -> Unit,
    onRefresh: () -> Unit,
    onUpdatePermissions: (ShareEntity, Int) -> Unit,
    onRevoke: (ShareEntity) -> Unit,
    onDismissNotice: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.shares_title)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.shares_back))
                    }
                },
                actions = {
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Default.Refresh, stringResource(R.string.shares_refresh))
                    }
                },
            )
        },
    ) { padding ->
        SharesContent(
            state = state,
            onCategory = onCategory,
            onRefresh = onRefresh,
            onUpdatePermissions = onUpdatePermissions,
            onRevoke = onRevoke,
            onDismissNotice = onDismissNotice,
            modifier = Modifier.padding(padding),
            showRefreshAction = false,
        )
    }
}

@Composable
@Suppress("LongParameterList")
@OptIn(ExperimentalMaterial3Api::class)
fun SharesContent(
    state: SharesUiState,
    onCategory: (ShareCategory) -> Unit,
    onRefresh: () -> Unit,
    onUpdatePermissions: (ShareEntity, Int) -> Unit,
    onRevoke: (ShareEntity) -> Unit,
    onDismissNotice: () -> Unit,
    modifier: Modifier = Modifier,
    showRefreshAction: Boolean = true,
    onBrowseResource: ((ResourceEntity) -> Unit)? = null,
    incomingContent: (@Composable () -> Unit)? = null,
    layout: SettingsBrowserLayout = SettingsBrowserLayout.DEFAULT_TABLE,
    onLayout: (SettingsBrowserLayout) -> Unit = {},
) {
    val visible =
        when (state.category) {
            ShareCategory.WITH_ME -> state.shares.filter(ShareEntity::sharedWithMe)
            ShareCategory.BY_ME ->
                state.shares.filter { share ->
                    !share.sharedWithMe &&
                        share.shareType != OcsShareType.PUBLIC_LINK.value
                }
            ShareCategory.PUBLIC ->
                state.shares.filter { share ->
                    !share.sharedWithMe &&
                        share.shareType == OcsShareType.PUBLIC_LINK.value
                }
        }

    if (state.category == ShareCategory.WITH_ME && incomingContent != null) {
        Column(modifier.fillMaxSize()) {
            ShareCategoryTabs(state.category, onCategory)
            incomingContent()
        }
        return
    }
    PullToRefreshBox(
        isRefreshing = state.loading || state.saving,
        onRefresh = onRefresh,
        modifier = modifier.fillMaxSize(),
    ) {
        Column(Modifier.fillMaxSize()) {
            ShareCategoryTabs(state.category, onCategory)
            BrowserToolbar(false, layout, {}, {
                onLayout(SettingsBrowserLayout.entries[(layout.ordinal + 1) % SettingsBrowserLayout.entries.size])
            }) {
                Text(stringResource(state.category.labelRes), Modifier.weight(1f), maxLines = 1)
                if (showRefreshAction) {
                    IconButton(onClick = onRefresh) {
                        Icon(Icons.Default.Refresh, stringResource(R.string.incoming_refresh_folder))
                    }
                }
            }
            if (state.loading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center,
                ) {
                    CircularProgressIndicator()
                }
            } else if (visible.isEmpty()) {
                LazyColumn(Modifier.fillMaxSize()) { item { ShareEmpty(state.category) } }
            } else {
                ShareList(visible, onUpdatePermissions, onRevoke, onBrowseResource, layout)
            }
        }
    }
    ShareNotice(state, onDismissNotice)
}

@Composable
private fun ShareCategoryTabs(
    selected: ShareCategory,
    onCategory: (ShareCategory) -> Unit,
) {
    TabRow(selectedTabIndex = selected.ordinal) {
        ShareCategory.entries.forEach { category ->
            Tab(
                selected = selected == category,
                onClick = { onCategory(category) },
                text = { Text(stringResource(category.labelRes)) },
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList")
fun ResourceSharesScreen(
    state: SharesUiState,
    onNavigateBack: () -> Unit,
    onSearch: (String) -> Unit,
    onCreateRecipient: (ShareRecipient, Int) -> Unit,
    onCreatePublic: (String, String?, LocalDate?, Int) -> Unit,
    onUpdatePermissions: (ShareEntity, Int) -> Unit,
    onRevoke: (ShareEntity) -> Unit,
    onDismissNotice: () -> Unit,
    modifier: Modifier = Modifier,
    initialInviteOpen: Boolean = false,
) {
    val context = LocalContext.current
    var showInvite by rememberSaveable { mutableStateOf(initialInviteOpen) }
    var showPublic by rememberSaveable { mutableStateOf(false) }
    val internalShares = state.resourceShares.filter { it.shareType != OcsShareType.PUBLIC_LINK.value }
    val sharingEnabled = state.account?.sharingEnabled == true
    val publicSharingEnabled = sharingEnabled && state.account?.publicSharingEnabled == true

    ModalBottomSheet(
        onDismissRequest = onNavigateBack,
        modifier = modifier,
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxWidth(),
            contentPadding =
                androidx.compose.foundation.layout.PaddingValues(
                    start = OpenCloudDimensions.SpacingMd,
                    end = OpenCloudDimensions.SpacingMd,
                    bottom = OpenCloudDimensions.SpacingXl,
                ),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            item {
                Text(
                    text = state.resource?.name ?: stringResource(R.string.share_metadata_fallback_name),
                    style = MaterialTheme.typography.headlineSmall,
                )
            }
            item {
                Text(stringResource(R.string.shares_internal_heading), style = MaterialTheme.typography.titleMedium)
            }
            item {
                Text(
                    stringResource(R.string.shares_internal_description),
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            if (sharingEnabled) {
                item {
                    Button(
                        onClick = { showInvite = true },
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Icon(Icons.Default.Person, null)
                        Text(" " + stringResource(R.string.shares_add_people))
                    }
                }
            } else {
                item {
                    Text(
                        stringResource(R.string.shares_not_supported),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            if (internalShares.isEmpty()) {
                item {
                    Text(
                        stringResource(R.string.shares_no_internal_shares),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            } else {
                items(internalShares, key = { "internal-${it.remoteId}" }) { share ->
                    ShareRow(share, onUpdatePermissions, onRevoke)
                }
            }
            externalSharing(
                state,
                publicSharingEnabled,
                { state.createdPublicLink?.let(context::copyPublicLink) ?: run { showPublic = true } },
                onUpdatePermissions,
                onRevoke,
            )
            if (state.loading || state.saving) {
                item {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.Center,
                    ) {
                        CircularProgressIndicator()
                    }
                }
            }
        }
    }
    if (showInvite && sharingEnabled) {
        InviteSheet(
            state = state,
            onDismiss = { showInvite = false },
            onSearch = onSearch,
            onCreate = onCreateRecipient,
        )
    }
    if (showPublic && publicSharingEnabled) {
        PublicLinkSheet(
            account = state.account,
            folder = state.resource?.kind?.name == "FOLDER",
            onDismiss = { showPublic = false },
            onCreate = onCreatePublic,
        )
    }
    ShareNotice(
        state.copy(message = state.message.takeIf { state.createdPublicLink == null }),
        onDismissNotice,
    )
}

private fun androidx.compose.foundation.lazy.LazyListScope.externalSharing(
    state: SharesUiState,
    enabled: Boolean,
    onCreateOrCopy: () -> Unit,
    onUpdatePermissions: (ShareEntity, Int) -> Unit,
    onRevoke: (ShareEntity) -> Unit,
) {
    val publicLinks = state.resourceShares.filter { it.shareType == OcsShareType.PUBLIC_LINK.value }
    item {
        Text(
            stringResource(R.string.shares_external_heading),
            modifier = Modifier.padding(top = OpenCloudDimensions.SpacingSm),
            style = MaterialTheme.typography.titleMedium,
        )
    }
    item {
        Text(
            stringResource(R.string.shares_external_description),
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodyMedium,
        )
    }
    if (enabled) {
        item {
            Button(
                onClick = {
                    onCreateOrCopy()
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Icon(
                    if (state.createdPublicLink == null) Icons.Default.Link else Icons.Default.ContentCopy,
                    null,
                )
                Text(
                    " " +
                        stringResource(
                            if (state.createdPublicLink ==
                                null
                            ) {
                                R.string.shares_create_public_link
                            } else {
                                R.string.shares_copy_link
                            },
                        ),
                )
            }
        }
    } else {
        item {
            Text(
                stringResource(R.string.shares_public_not_supported),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    if (publicLinks.isEmpty()) {
        item {
            Text(
                stringResource(R.string.shares_no_public_links),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    } else {
        items(publicLinks, key = { "public-${it.remoteId}" }) { share ->
            ShareRow(share, onUpdatePermissions, onRevoke)
        }
    }
}

@Composable
private fun ShareList(
    values: List<ShareEntity>,
    onUpdatePermissions: (ShareEntity, Int) -> Unit,
    onRevoke: (ShareEntity) -> Unit,
    onBrowseResource: ((ResourceEntity) -> Unit)?,
    layout: SettingsBrowserLayout,
) = BrowserContent(values, { it.remoteId }, layout) { share ->
    ShareRow(share, onUpdatePermissions, onRevoke, onBrowseResource, layout)
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun ShareRow(
    share: ShareEntity,
    onUpdatePermissions: (ShareEntity, Int) -> Unit,
    onRevoke: (ShareEntity) -> Unit,
    onBrowseResource: ((ResourceEntity) -> Unit)? = null,
    layout: SettingsBrowserLayout = SettingsBrowserLayout.DEFAULT_TABLE,
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var menu by remember { mutableStateOf(false) }
    var copying by remember { mutableStateOf(false) }
    var copyError by remember { mutableStateOf<String?>(null) }
    var editing by rememberSaveable(share.remoteId) { mutableStateOf(false) }
    val title = shareRowTitle(share)
    val expiration =
        if (share.expiresAtEpochMillis !=
            null
        ) {
            " • ${stringResource(R.string.share_metadata_expires_short)}"
        } else {
            ""
        }
    val copyFailureMessage = stringResource(R.string.shares_copy_link_failed)
    val copyLink = {
        copying = true
        scope.launch {
            try {
                val link =
                    withContext(
                        Dispatchers.IO,
                    ) { ShareManager(context).publicLink(share.accountId, share.remoteId) }
                context.copyPublicLink(link)
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                copyError = copyFailureMessage
            } finally {
                copying = false
            }
        }
    }
    BrowserEntry(
        layout,
        onOpen = { editing = true },
        name = { Text(title, maxLines = 1) },
        metadata = { Text(sharedItemSummary(share) + expiration, maxLines = 2) },
        thumbnail = { modifier ->
            Box(modifier, contentAlignment = Alignment.Center) {
                Icon(
                    if (share.shareType ==
                        OcsShareType.PUBLIC_LINK.value
                    ) {
                        Icons.Default.Link
                    } else {
                        Icons.Default.Group
                    },
                    null,
                )
            }
        },
        actions = {
            IconButton(onClick = { menu = true }) {
                Icon(Icons.Default.MoreVert, stringResource(R.string.shares_actions_for_file, title))
            }
        },
    )
    if (menu) {
        BrowserActionSheet(title, { menu = false }) {
            BrowserAction(stringResource(R.string.incoming_details), Icons.Default.Info) {
                menu = false
                editing = true
            }
            if (share.shareType == OcsShareType.PUBLIC_LINK.value && !copying) {
                BrowserAction(stringResource(R.string.shares_copy_link), Icons.Default.Link) {
                    menu = false
                    copyLink()
                }
            }
        }
    }
    if (editing) {
        ManageShareDialog(
            share = share,
            onDismiss = { editing = false },
            onUpdate = onUpdatePermissions,
            onRevoke = onRevoke,
            onBrowseResource = onBrowseResource,
        )
    }
    copyError?.let { message ->
        AlertDialog(onDismissRequest = { copyError = null }, text = { Text(message) }, confirmButton = {
            TextButton(onClick = { copyError = null }) { Text(stringResource(R.string.share_ok)) }
        })
    }
}

@Composable
private fun ManageShareDialog(
    share: ShareEntity,
    onDismiss: () -> Unit,
    onUpdate: (ShareEntity, Int) -> Unit,
    onRevoke: (ShareEntity) -> Unit,
    onBrowseResource: ((ResourceEntity) -> Unit)?,
) {
    var permissions by rememberSaveable { mutableIntStateOf(share.permissions) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.shares_details_title)) },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                ShareResourceDetails(
                    share,
                    onBrowseResource?.let { browse ->
                        { resource ->
                            onDismiss()
                            browse(resource)
                        }
                    },
                )
                Text(stringResource(R.string.shares_permissions), style = MaterialTheme.typography.titleSmall)
                if (share.shareType == OcsShareType.PUBLIC_LINK.value) {
                    PublicLinkPermissions(permissions, share.isFolder) { permissions = it }
                } else {
                    PermissionControls(permissions, share.isFolder) { permissions = it }
                }
                TextButton(
                    onClick = {
                        onRevoke(share)
                        onDismiss()
                    },
                ) {
                    Text(stringResource(R.string.shares_revoke), color = MaterialTheme.colorScheme.error)
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onUpdate(share, permissions)
                    onDismiss()
                },
            ) {
                Text(stringResource(R.string.shares_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.shares_cancel))
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun InviteSheet(
    state: SharesUiState,
    onDismiss: () -> Unit,
    onSearch: (String) -> Unit,
    onCreate: (ShareRecipient, Int) -> Unit,
) {
    var query by rememberSaveable { mutableStateOf("") }
    var permissions by rememberSaveable { mutableIntStateOf(1) }
    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .imePadding()
                    .verticalScroll(
                        rememberScrollState(),
                    ).padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            Text(stringResource(R.string.shares_invite_title), style = MaterialTheme.typography.titleLarge)
            OutlinedTextField(
                value = query,
                onValueChange = {
                    query = it
                    onSearch(it)
                },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.shares_search_recipients)) },
            )
            PermissionControls(permissions, state.resource?.kind?.name == "FOLDER") { permissions = it }
            state.recipients.forEach { recipient ->
                val recipientType =
                    stringResource(
                        if (recipient.type ==
                            OcsShareType.GROUP
                        ) {
                            R.string.shares_recipient_group
                        } else {
                            R.string.shares_recipient_user
                        },
                    )
                ListItem(
                    headlineContent = { Text(recipient.label) },
                    supportingContent = {
                        Text(
                            listOfNotNull(
                                recipientType,
                                recipient.additionalInfo,
                            ).joinToString(" • "),
                        )
                    },
                    modifier =
                        Modifier.clickable {
                            onCreate(recipient, permissions)
                            onDismiss()
                        },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PublicLinkSheet(
    account: AccountEntity?,
    folder: Boolean,
    onDismiss: () -> Unit,
    onCreate: (String, String?, LocalDate?, Int) -> Unit,
) {
    var label by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var expiration by rememberSaveable { mutableStateOf("") }
    var permissions by rememberSaveable { mutableIntStateOf(1) }
    val expirationRequired = account?.publicLinkExpirationEnforced == true
    val expirationDate = runCatching { LocalDate.parse(expiration) }.getOrNull()
    val expirationValid = expiration.isBlank() || expirationDate?.let { !it.isBefore(LocalDate.now()) } == true
    val valid =
        password.isNotBlank() &&
            (!expirationRequired || expirationDate != null) &&
            expirationValid

    ModalBottomSheet(onDismissRequest = onDismiss) {
        Column(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .imePadding()
                    .verticalScroll(
                        rememberScrollState(),
                    ).padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            Text(stringResource(R.string.shares_create_public_link), style = MaterialTheme.typography.titleLarge)
            OutlinedTextField(
                value = label,
                onValueChange = { label = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.shares_link_name_optional)) },
            )
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text(stringResource(R.string.shares_password_required)) },
                supportingText = { Text(stringResource(R.string.shares_password_required_by_server)) },
                visualTransformation = PasswordVisualTransformation(),
            )
            OutlinedTextField(
                value = expiration,
                onValueChange = { expiration = it },
                modifier = Modifier.fillMaxWidth(),
                label = {
                    Text(
                        if (expirationRequired) {
                            stringResource(R.string.shares_expiration_required)
                        } else {
                            stringResource(R.string.shares_expiration_optional)
                        },
                    )
                },
                supportingText = {
                    Text(
                        listOfNotNull(
                            account?.publicLinkExpirationDays?.let { days ->
                                pluralStringResource(R.plurals.shares_expiration_max_days, days, days)
                            },
                            if (!expirationValid) stringResource(R.string.shares_expiration_future) else null,
                        ).joinToString(" • "),
                    )
                },
            )
            Text(stringResource(R.string.shares_permissions), style = MaterialTheme.typography.titleMedium)
            PublicLinkPermissions(permissions, folder) { permissions = it }
            Button(
                onClick = {
                    onCreate(label, password, expirationDate, permissions)
                    onDismiss()
                },
                enabled = valid,
            ) {
                Icon(Icons.Default.ContentCopy, null)
                Text(" " + stringResource(R.string.shares_create_link))
            }
        }
    }
}

@Composable
private fun PublicLinkPermissions(
    value: Int,
    folder: Boolean,
    onChange: (Int) -> Unit,
) {
    val roles =
        if (folder) {
            listOf(
                1 to R.string.shares_permission_view_download,
                5 to R.string.shares_permission_view_download_upload,
                15 to R.string.shares_permission_edit_contents,
                4 to R.string.shares_permission_upload_only,
            )
        } else {
            listOf(1 to R.string.shares_permission_view_download, 3 to R.string.shares_permission_view_edit)
        }
    Column {
        roles.forEach { (permissions, labelRes) ->
            Row(
                Modifier
                    .fillMaxWidth()
                    .heightIn(min = OpenCloudDimensions.TouchTarget)
                    .selectable(value == permissions, role = androidx.compose.ui.semantics.Role.RadioButton) {
                        onChange(permissions)
                    },
                verticalAlignment = Alignment.CenterVertically,
            ) {
                androidx.compose.material3.RadioButton(selected = value == permissions, onClick = null)
                Text(stringResource(labelRes), Modifier.padding(OpenCloudDimensions.SpacingSm))
            }
        }
    }
}

@Composable
private fun PermissionControls(
    value: Int,
    folder: Boolean,
    onChange: (Int) -> Unit,
) {
    Column {
        PermissionToggle(stringResource(R.string.shares_permission_read), value and 1 != 0, enabled = false) {}
        PermissionToggle(stringResource(R.string.shares_permission_update), value and 2 != 0) {
            onChange(value.toggle(2, it) or 1)
        }
        if (folder) {
            PermissionToggle(stringResource(R.string.shares_permission_create), value and 4 != 0) {
                onChange(value.toggle(4, it) or 1)
            }
            PermissionToggle(stringResource(R.string.shares_permission_delete), value and 8 != 0) {
                onChange(value.toggle(8, it) or 1)
            }
        }
        PermissionToggle(stringResource(R.string.shares_permission_reshare), value and 16 != 0) {
            onChange(value.toggle(16, it) or 1)
        }
    }
}

@Composable
private fun PermissionToggle(
    label: String,
    checked: Boolean,
    enabled: Boolean = true,
    onChange: (Boolean) -> Unit,
) = Row(verticalAlignment = Alignment.CenterVertically) {
    Checkbox(checked, onChange, enabled = enabled)
    Text(label)
}

private fun Int.toggle(
    flag: Int,
    enabled: Boolean,
) = if (enabled) this or flag else this and flag.inv()

@Composable
private fun ShareEmpty(category: ShareCategory) =
    Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.Share, null)
            Text(
                when (category) {
                    ShareCategory.WITH_ME -> stringResource(R.string.shares_empty_with_me)
                    ShareCategory.BY_ME -> stringResource(R.string.shares_empty_by_me)
                    ShareCategory.PUBLIC -> stringResource(R.string.shares_empty_public)
                },
            )
        }
    }

@Composable
private fun ShareNotice(
    state: SharesUiState,
    onDismiss: () -> Unit,
) {
    val context = LocalContext.current
    val notice = state.error ?: state.message
    if (notice != null) {
        AlertDialog(
            onDismissRequest = onDismiss,
            title = {
                Text(
                    stringResource(
                        if (state.error !=
                            null
                        ) {
                            R.string.shares_dialog_error_title
                        } else {
                            R.string.shares_dialog_done_title
                        },
                    ),
                )
            },
            text = { Text(notice) },
            confirmButton = {
                Row {
                    state.createdPublicLink?.let { link ->
                        Button(
                            onClick = {
                                context.copyPublicLink(link)
                                onDismiss()
                            },
                        ) {
                            Text(stringResource(R.string.shares_copy_link))
                        }
                    }
                    TextButton(onClick = onDismiss) {
                        Text(stringResource(R.string.share_ok))
                    }
                }
            },
        )
    }
}

private fun Context.copyPublicLink(link: TransientPublicLink) {
    getSystemService(ClipboardManager::class.java)
        .setPrimaryClip(ClipData.newPlainText(getString(R.string.shares_clipboard_label), link.valueForClipboard()))
}

@Composable
private fun shareRowTitle(share: ShareEntity): String =
    if (share.shareType == OcsShareType.PUBLIC_LINK.value) {
        share.label?.takeIf(String::isNotBlank)
            ?: share.path.substringAfterLast('/').ifBlank { stringResource(R.string.shares_public_link_fallback) }
    } else {
        share.displayName ?: share.label ?: share.shareWith ?: share.path.substringAfterLast('/')
    }
