package eu.opencloud.android.next.ui

import androidx.activity.compose.BackHandler
import androidx.browser.customtabs.CustomTabsIntent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.core.net.toUri
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.BuildConfig
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.feature.account.AccountRoute
import eu.opencloud.android.next.feature.auth.AuthScreen
import eu.opencloud.android.next.feature.auth.AuthViewModel
import eu.opencloud.android.next.feature.auth.DevLoginConfiguration
import eu.opencloud.android.next.feature.files.BackupSettingsRoute
import eu.opencloud.android.next.feature.files.DeletedFilesRoute
import eu.opencloud.android.next.feature.files.FileBrowserDestinations
import eu.opencloud.android.next.feature.files.FileBrowserRoute
import eu.opencloud.android.next.feature.settings.SettingsRoute
import eu.opencloud.android.next.feature.shares.ResourceSharesRoute
import eu.opencloud.android.next.feature.shares.TopLevelSharesRoute
import eu.opencloud.android.next.feature.spaces.SpacesRoute
import eu.opencloud.android.next.feature.transfers.TransfersRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
@Suppress("CyclomaticComplexMethod", "LongMethod", "FunctionNaming", "ktlint:standard:function-naming")
fun OpenCloudNextApp(
    oauthCallback: String?,
    modifier: Modifier = Modifier,
    folderShortcut: String? = null,
    onConsumeFolderShortcut: () -> Unit = {},
    viewModel: AuthViewModel = viewModel(),
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var encryptedCleanupFailed by remember { mutableStateOf(false) }
    val state = viewModel.state.collectAsStateWithLifecycle()
    var destination by rememberSaveable(state.value.activeAccountId) { mutableStateOf(AppDestination.Files) }
    var nextBrowserAddRequest by remember(state.value.activeAccountId) { mutableIntStateOf(0) }
    var pendingBrowserAddRequest by remember(state.value.activeAccountId) { mutableIntStateOf(0) }
    var trashSpaceId by rememberSaveable(state.value.activeAccountId) { mutableStateOf<String?>(null) }
    var encryptedLocation by remember(state.value.activeAccountId) { mutableStateOf<VaultLocation?>(null) }
    var offlineUnavailableLocation by remember(state.value.activeAccountId) { mutableStateOf<VaultLocation?>(null) }
    var encryptedReturnRevision by remember(state.value.activeAccountId) { mutableIntStateOf(0) }
    var encryptedRootActions by remember(state.value.activeAccountId) { mutableStateOf(false) }
    var shareResource by remember(state.value.activeAccountId) { mutableStateOf<ResourceEntity?>(null) }
    var shortcutFolder by remember(state.value.activeAccountId) { mutableStateOf<ResourceEntity?>(null) }

    var sharedShortcut by remember(state.value.activeAccountId) {
        mutableStateOf<eu.opencloud.android.next.core.sync.SharedFolderRequest?>(null)
    }

    FolderShortcutEntry(
        folderShortcut,
        state.value.activeAccountId,
        state.value.isRestoringSession,
        viewModel::switchAccount,
        {
            shortcutFolder = it
            destination = AppDestination.Files
        },
        onConsumeFolderShortcut,
        openShared = {
            sharedShortcut = it
            destination = AppDestination.Files
        },
    )

    LaunchedEffect(oauthCallback) {
        oauthCallback?.let(viewModel::completeOidcCallback)
    }

    Surface(modifier = modifier.fillMaxSize()) {
        when {
            state.value.isRestoringSession ->
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            state.value.activeAccountId != null -> {
                val accountId = requireNotNull(state.value.activeAccountId)
                when (destination) {
                    AppDestination.Files ->
                        Box(modifier = Modifier.fillMaxSize()) {
                            FileBrowserRoute(
                                accountId = accountId,
                                modifier =
                                    if (encryptedLocation !=
                                        null
                                    ) {
                                        Modifier.clearAndSetSemantics {}
                                    } else {
                                        Modifier
                                    },
                                encryptedReturnRevision = encryptedReturnRevision,
                                shortcutFolder = shortcutFolder,
                                sharedShortcut = sharedShortcut,
                                onConsumeShortcutFolder = { shortcutFolder = null },
                                releaseVersion = BuildConfig.VERSION_NAME,
                                openAddMenuRequest = pendingBrowserAddRequest,
                                onConsumeAddMenuRequest = { pendingBrowserAddRequest = 0 },
                                destinations =
                                    FileBrowserDestinations(
                                        onOpenTransfers = { destination = AppDestination.Transfers },
                                        onOpenDeletedFiles = {
                                            trashSpaceId = null
                                            destination = AppDestination.DeletedFiles
                                        },
                                        onOpenSettings = { destination = AppDestination.Settings },
                                        onOpenAccount = { destination = AppDestination.Account },
                                        onOpenEncryptedOffline = { destination = AppDestination.Vaults },
                                        onOpenEncryptedLocation = { location ->
                                            dispatchOfflineAwareEncryptedLocation(
                                                location,
                                                onOpen = {
                                                    encryptedRootActions = false
                                                    encryptedLocation = it
                                                },
                                                onUnavailable = { offlineUnavailableLocation = it },
                                            )
                                        },
                                        onEncryptedLocationActions = { location ->
                                            dispatchOfflineAwareEncryptedLocation(
                                                location,
                                                onOpen = {
                                                    encryptedRootActions = true
                                                    encryptedLocation = it
                                                },
                                                onUnavailable = { offlineUnavailableLocation = it },
                                            )
                                        },
                                        onShareResource = { shareResource = it },
                                    ),
                                sharesContent = { padding, onBrowseResource ->
                                    TopLevelSharesRoute(
                                        accountId = accountId,
                                        modifier = Modifier.padding(padding),
                                        onBrowseResource = onBrowseResource,
                                        initialFolder = sharedShortcut,
                                        onConsumeInitialFolder = { sharedShortcut = null },
                                    )
                                },
                                spacesContent = { padding, onOpenSpace, refreshToken ->
                                    SpacesRoute(
                                        accountId = accountId,
                                        onOpenSpace = onOpenSpace,
                                        refreshToken = refreshToken + encryptedReturnRevision,
                                        onOpenEncryptedLocation = { location ->
                                            dispatchOfflineAwareEncryptedLocation(
                                                location,
                                                onOpen = {
                                                    encryptedRootActions = false
                                                    encryptedLocation = it
                                                },
                                                onUnavailable = { offlineUnavailableLocation = it },
                                            )
                                        },
                                        onEncryptedLocationActions = { location ->
                                            dispatchOfflineAwareEncryptedLocation(
                                                location,
                                                onOpen = {
                                                    encryptedRootActions = true
                                                    encryptedLocation = it
                                                },
                                                onUnavailable = { offlineUnavailableLocation = it },
                                            )
                                        },
                                        onOpenTrash = {
                                            trashSpaceId = it
                                            destination = AppDestination.DeletedFiles
                                        },
                                        modifier = Modifier.padding(padding),
                                    )
                                },
                            )
                            encryptedLocation?.let { location ->
                                Surface(Modifier.fillMaxSize()) {
                                    if (location.isDisabled) {
                                        EncryptedDisabledSpaceManagementDialog(
                                            accountId = accountId,
                                            location = location,
                                            onClose = { encryptedLocation = null },
                                            onLifecycleChange = { changed ->
                                                encryptedLocation = null
                                                scope.launch {
                                                    try {
                                                        withContext(Dispatchers.IO) {
                                                            val identity =
                                                                eu.opencloud.android.next.core.security.VaultIdentity(
                                                                    location.accountId,
                                                                    location.canonicalServer,
                                                                    location.driveId,
                                                                    location.remoteVaultId,
                                                                )
                                                            eu.opencloud.android.next.core.sync
                                                                .VaultOfflineStore(
                                                                    context,
                                                                ).remove(identity)
                                                            if (changed == null) {
                                                                eu.opencloud.android.next.core.security
                                                                    .VaultKeyStore(
                                                                        context,
                                                                    ).forget(identity)
                                                                eu.opencloud.android.next.core.security
                                                                    .VaultPreferences(
                                                                        context,
                                                                    ).remove(identity)
                                                            }
                                                        }
                                                        encryptedReturnRevision++
                                                    } catch (cancelled: kotlinx.coroutines.CancellationException) {
                                                        throw cancelled
                                                    } catch (_: Exception) {
                                                        encryptedCleanupFailed = true
                                                        encryptedReturnRevision++
                                                    }
                                                }
                                            },
                                        )
                                    } else {
                                        VaultRoute(
                                            accountId = accountId,
                                            initialLocation = location,
                                            openMenuAfterUnlock = encryptedRootActions,
                                            onNavigateBack = {
                                                encryptedLocation = null
                                                encryptedReturnRevision++
                                            },
                                        )
                                    }
                                }
                            }
                            shareResource?.let { resource ->
                                ResourceSharesRoute(
                                    accountId = accountId,
                                    resource = resource,
                                    onNavigateBack = { shareResource = null },
                                )
                            }
                            offlineUnavailableLocation?.let { location ->
                                EncryptedOfflineUnavailableDialog(location) { offlineUnavailableLocation = null }
                            }
                        }
                    AppDestination.Vaults ->
                        VaultRoute(accountId = accountId, offlineCatalog = true, onNavigateBack = {
                            destination =
                                AppDestination.Files
                        })
                    AppDestination.Transfers ->
                        TransfersRoute(
                            accountId = accountId,
                            onNavigateBack = { destination = AppDestination.Files },
                            onOpenFileActions = {
                                nextBrowserAddRequest += 1
                                pendingBrowserAddRequest = nextBrowserAddRequest
                                destination = AppDestination.Files
                            },
                        )
                    AppDestination.DeletedFiles ->
                        DeletedFilesRoute(
                            accountId = accountId,
                            initialSpaceId = trashSpaceId,
                            onNavigateBack = { destination = AppDestination.Files },
                        )
                    AppDestination.Settings ->
                        SettingsRoute(
                            accountId = accountId,
                            onNavigateBack = { destination = AppDestination.Files },
                            onOpenBackupSettings = { destination = AppDestination.BackupSettings },
                        )
                    AppDestination.Security ->
                        eu.opencloud.android.next.feature.settings
                            .SecuritySettingsScreen(accountId = accountId, onNavigateBack = {
                                destination =
                                    AppDestination.Settings
                            })
                    AppDestination.BackupSettings ->
                        BackupSettingsRoute(
                            accountId = accountId,
                            onNavigateBack = { destination = AppDestination.Settings },
                        )
                    AppDestination.Account ->
                        AccountRoute(
                            activeAccountId = accountId,
                            onNavigateBack = { destination = AppDestination.Files },
                            onAccountSelect = {
                                viewModel.switchAccount(it)
                                destination = AppDestination.Files
                            },
                            onAccountRemove = {
                                viewModel.accountRemoved(it)
                                destination = AppDestination.Files
                            },
                            onAddAccount = {
                                viewModel.accountRemoved(null)
                                destination = AppDestination.Files
                            },
                        )
                }
            }
            else ->
                AuthScreen(
                    state = state.value,
                    devLogin =
                        if (BuildConfig.DEBUG) {
                            DevLoginConfiguration(
                                serverUrl = BuildConfig.DEV_SERVER_URL,
                                username = BuildConfig.DEV_SERVER_USERNAME,
                                password = BuildConfig.DEV_SERVER_PASSWORD,
                            )
                        } else {
                            null
                        },
                    onDiscover = viewModel::discover,
                    onBasicLogin = viewModel::loginBasic,
                    onAppTokenLogin = viewModel::loginBasicDirect,
                    onDevLogin = { configuration ->
                        viewModel.loginBasicDirect(
                            configuration.serverUrl,
                            configuration.username,
                            configuration.password,
                        )
                    },
                    onBeginOidc = {
                        viewModel.beginOidc()?.let { url ->
                            CustomTabsIntent.Builder().build().launchUrl(context, url.toUri())
                        }
                    },
                )
        }
    }
    if (encryptedCleanupFailed) {
        AlertDialog(
            onDismissRequest = { encryptedCleanupFailed = false },
            title = { Text(stringResource(R.string.vault_offline_cleanup_failed)) },
            confirmButton = {
                TextButton(onClick = { encryptedCleanupFailed = false }) {
                    Text(stringResource(R.string.vault_close))
                }
            },
        )
    }
    BackHandler(
        enabled =
            state.value.activeAccountId != null &&
                (
                    shareResource != null ||
                        (
                            destination !in
                                listOf(
                                    AppDestination.Files,
                                    AppDestination.Settings,
                                    AppDestination.Security,
                                    AppDestination.Vaults,
                                )
                        )
                ),
    ) {
        if (shareResource != null) {
            shareResource = null
        } else {
            destination =
                if (destination in
                    listOf(AppDestination.BackupSettings, AppDestination.Security)
                ) {
                    AppDestination.Settings
                } else {
                    AppDestination.Files
                }
        }
    }
}

private enum class AppDestination {
    Files,
    DeletedFiles,
    Transfers,
    Settings,
    BackupSettings,
    Security,
    Account,
    Vaults,
}
