package eu.opencloud.android.next.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CameraAlt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.R
import eu.opencloud.android.next.SensitiveWindowProtection
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.ui.FileNameConflictDialog
import eu.opencloud.android.next.feature.files.R as FilesR

// The route owns the model; only its lifecycle and prompt controller receive it. UI content is state-hoisted.
@Suppress("ViewModelForwarding", "LongParameterList", "LongMethod", "CyclomaticComplexMethod")
@Composable
fun VaultRoute(
    accountId: String,
    onNavigateBack: () -> Unit,
    initialLocation: VaultLocation? = null,
    openMenuAfterUnlock: Boolean = false,
    offlineCatalog: Boolean = false,
    vaultViewModel: VaultViewModel =
        viewModel(
            key = "vault-$accountId",
            factory =
                ViewModelProvider.AndroidViewModelFactory.getInstance(
                    LocalContext.current.applicationContext as android.app.Application,
                ),
        ),
) {
    val context = LocalContext.current
    val activity = remember(context) { context.findComponentActivity() }
    val state by vaultViewModel.state.collectAsStateWithLifecycle()
    val revision = state.lockRevision
    var boundaryRequest by remember(accountId, revision) { mutableStateOf<BoundaryTransferRequest?>(null) }
    val prompts = remember(activity, vaultViewModel) { VaultPromptController(activity, vaultViewModel) }
    VaultRouteLifecycle(
        activity,
        vaultViewModel,
        accountId,
        initialLocation,
        openMenuAfterUnlock,
        offlineCatalog,
        prompts,
    )
    val lifecycleState by activity.lifecycle.currentStateFlow.collectAsStateWithLifecycle()
    val automaticPrompt =
        remember(accountId, state.selectedLocation?.id, state.selectedTitle) {
            VaultAutomaticBiometricPrompt()
        }
    LaunchedEffect(automaticPrompt, state, lifecycleState) {
        if (automaticPrompt.consumeIfReady(state, lifecycleState == Lifecycle.State.RESUMED)) {
            prompts.showUnlock(state.selectedTitle.orEmpty())
        }
    }
    val safLaunchers = rememberVaultSafLaunchers(vaultViewModel)
    val openWith = rememberVaultOpenWith(vaultViewModel, state)
    var scannerLease by remember(accountId, revision) { mutableStateOf<VaultScanLease?>(null) }
    val uploadSnackbar = rememberVaultUploadSnackbar(state.queuedUploadCount, scannerLease == null)
    var managementLocation by remember(accountId, revision) { mutableStateOf<VaultLocation?>(null) }

    fun lockVault() {
        prompts.cancel()
        vaultViewModel.lock()
    }

    fun handleBack() {
        prompts.cancel()
        if (navigateVaultDestinationBack(state, vaultViewModel)) return
        if (initialLocation != null && shouldExitDirectVault(state)) {
            onNavigateBack()
        } else {
            navigateVaultBack(state, vaultViewModel, onNavigateBack)
        }
    }

    val callbacks =
        VaultRouteCallbacks(
            onNavigateBack = ::handleBack,
            onSelectLocation = vaultViewModel::selectLocation,
            onOpenDiscoveryFolder = vaultViewModel::openDiscoveryFolder,
            onSelectVaultFolder = vaultViewModel::selectVaultFolder,
            onUnlock = vaultViewModel::unlock,
            onBiometricUnlock = { prompts.showUnlock(state.selectedTitle.orEmpty()) },
            onBiometricEnroll = { prompts.showEnrollment(state.selectedTitle.orEmpty()) },
            onForgetBiometric = { vaultViewModel.forgetBiometric(revision) },
            onOpenVaultFolder = vaultViewModel::openVaultFolder,
            onOpenPreview = vaultViewModel::openPreview,
            onLoadThumbnail = vaultViewModel::loadThumbnail,
            onDismissPreview = vaultViewModel::dismissPreview,
            onOpenWithPreview = { openWith(null) },
            onSavePreviewText = vaultViewModel::savePreviewText,
            onSavePreviewTextRange = vaultViewModel::savePreviewTextRange,
            onUp = vaultViewModel::up,
            onLock = ::lockVault,
            onRetry = vaultViewModel::retry,
            onDirectoryPage = vaultViewModel::directoryPage,
            onShowHidden = vaultViewModel::setShowHidden,
            onAcceptBiometricOffer = {
                vaultViewModel.acceptBiometricOffer()
                prompts.showEnrollment(state.selectedTitle.orEmpty())
            },
            onRememberOnPhone = vaultViewModel::rememberOnPhone,
            onDeclineBiometricOffer = vaultViewModel::declineBiometricOffer,
            onShowRootActions = { managementLocation = vaultViewModel.editTarget(revision) },
            onManageLocation = {
                managementLocation = vaultViewModel.managementTarget(revision)
                vaultViewModel.dismissRootActions()
            },
            onDismissRootActions = vaultViewModel::dismissRootActions,
            onRenameRoot = { vaultViewModel.renameRoot(it, revision) },
            onDeleteRoot = { vaultViewModel.deleteRoot(revision) },
            onShowOffline = vaultViewModel::showOfflineCatalog,
            onKeepDirectoryOffline = vaultViewModel::keepDirectoryOffline,
            onRemoveOffline = vaultViewModel::removeOfflineCopy,
            onCreateFolder = vaultViewModel::createFolder,
            onLoadDestinationFolders = vaultViewModel::loadDestinationFolders,
            onBeginDestinationPicker = vaultViewModel::beginDestinationPicker,
            onDestinationPage = vaultViewModel::destinationPage,
            onOtherLocation = { id, move -> vaultViewModel.prepareBoundaryTransfer(id, move) { boundaryRequest = it } },
            onResolveTransferConflict = vaultViewModel::resolveTransferConflict,
            onDismissDestinationPicker = vaultViewModel::dismissDestinationPicker,
            onUpload = safLaunchers.upload,
            onScan = { scannerLease = vaultViewModel.prepareScanner() },
            onEntryAction = { id, action, value ->
                if (action == VaultEntryAction.SAVE_COPY) {
                    safLaunchers.export(id)
                } else if (action == VaultEntryAction.OPEN_WITH) {
                    openWith(id)
                } else {
                    vaultViewModel.onEntryAction(id, action, value)
                }
            },
        )
    BackHandler(onBack = ::handleBack)
    val activeScanner = scannerLease
    if (activeScanner != null && state.mode == VaultRouteMode.CONTENTS) {
        VaultScannerRoute(activeScanner.destinationLabel, activeScanner.isValid, activeScanner.upload) {
            scannerLease = null
            if (state.mode == VaultRouteMode.CONTENTS) vaultViewModel.retry()
        }
    } else {
        VaultScreen(state, callbacks, uploadSnackbar = uploadSnackbar, accountId = accountId)
    }
    boundaryRequest?.let { request ->
        BoundaryDestinationDialog(request, onDismiss = { boundaryRequest = null })
    }
    managementLocation?.takeIf { state.mode == VaultRouteMode.CONTENTS }?.let { location ->
        val isUnlocked = { vaultViewModel.isManagementUnlocked(location, revision) }
        if (location.kind == eu.opencloud.android.next.core.sync.VaultLocationKind.SPACE_VAULT) {
            EncryptedSpaceManagementDialog(
                accountId,
                location,
                isUnlocked,
                onClose = { managementLocation = null },
                onChange = { vaultViewModel.managedSpaceChanged(it, revision) },
                onLifecycleChange = {
                    managementLocation = null
                    prompts.cancel()
                    vaultViewModel.managedSpaceLifecycleChanged(revision, onNavigateBack)
                },
                onInvalidate = {
                    managementLocation = null
                    lockVault()
                },
            )
        } else {
            EncryptedFolderSharingDialog(
                accountId,
                location,
                isUnlocked,
                onClose = { managementLocation = null },
                onInvalidate = {
                    managementLocation = null
                    lockVault()
                },
            )
        }
    }
}

private fun shouldExitDirectVault(state: VaultRouteState): Boolean =
    state.preview == null &&
        (
            state.mode == VaultRouteMode.CATALOG ||
                state.mode == VaultRouteMode.UNLOCK ||
                (state.mode == VaultRouteMode.CONTENTS && state.currentPath.isEmpty())
        )

@Composable
@Suppress("LongParameterList") // Explicit lifecycle owner, target and prompt binding.
private fun VaultRouteLifecycle(
    activity: ComponentActivity,
    viewModel: VaultViewModel,
    accountId: String,
    initialLocation: VaultLocation?,
    openMenuAfterUnlock: Boolean,
    offlineCatalog: Boolean,
    prompts: VaultPromptController,
) {
    DisposableEffect(activity, viewModel, accountId, initialLocation, openMenuAfterUnlock, offlineCatalog, prompts) {
        val releaseSensitiveWindow = SensitiveWindowProtection.acquire(activity)

        fun lock() {
            prompts.cancel()
            viewModel.onDeviceLocked()
        }
        val observer =
            LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_START) viewModel.onRouteStarted()
                if (event == Lifecycle.Event.ON_STOP) {
                    prompts.cancel()
                    viewModel.onRouteStopped()
                }
            }
        val screenOffReceiver =
            object : android.content.BroadcastReceiver() {
                override fun onReceive(
                    context: Context,
                    intent: Intent,
                ) {
                    if (intent.action == Intent.ACTION_SCREEN_OFF) lock()
                }
            }
        ContextCompat.registerReceiver(
            activity,
            screenOffReceiver,
            IntentFilter(Intent.ACTION_SCREEN_OFF),
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        activity.lifecycle.addObserver(observer)
        viewModel.enterRoute(accountId, initialLocation, openMenuAfterUnlock, offlineCatalog)
        onDispose {
            prompts.cancel()
            activity.unregisterReceiver(screenOffReceiver)
            activity.lifecycle.removeObserver(observer)
            viewModel.leaveRoute()
            releaseSensitiveWindow()
        }
    }
}

internal fun navigateVaultBack(
    state: VaultRouteState,
    viewModel: VaultViewModel,
    onNavigateBack: () -> Unit,
) {
    when {
        state.preview != null -> viewModel.dismissPreview()
        state.mode == VaultRouteMode.DISCOVERY && state.currentPath.isNotEmpty() -> viewModel.up()
        state.mode == VaultRouteMode.DISCOVERY -> viewModel.showCatalog()
        state.mode == VaultRouteMode.CONTENTS && state.currentPath.isNotEmpty() -> viewModel.up()
        state.mode == VaultRouteMode.CONTENTS -> viewModel.returnFromVault()
        state.mode == VaultRouteMode.UNLOCK -> viewModel.returnFromVault()
        else -> onNavigateBack()
    }
}

private fun VaultRouteState.confirmationKey() =
    VaultConfirmationKey(
        selectedLocation?.id,
        selectedTitle,
        mode,
        lockRevision,
        currentPath,
    )

private data class VaultConfirmationKey(
    val locationId: String?,
    val title: String?,
    val mode: VaultRouteMode,
    val lockRevision: Long,
    val path: String,
)

/** The route retains notification state while scanner content temporarily replaces the browser. */
@Composable
internal fun rememberVaultUploadSnackbar(
    queuedUploadCount: Long,
    visible: Boolean = true,
): SnackbarHostState {
    val snackbar = remember { SnackbarHostState() }
    var announced by remember { mutableLongStateOf(0L) }
    val message = stringResource(R.string.vault_background_upload_queued)
    LaunchedEffect(queuedUploadCount, visible) {
        if (visible && queuedUploadCount > announced) {
            announced = queuedUploadCount
            snackbar.showSnackbar(message)
        }
    }
    return snackbar
}

/** Hoisted route content for UI tests and previews. Password and preview state are never saveable. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("CyclomaticComplexMethod", "LongMethod") // Mode, prompts and independently visible secure overlays.
fun VaultScreen(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    modifier: Modifier = Modifier,
    uploadSnackbar: SnackbarHostState = remember { SnackbarHostState() },
    accountId: String? = null,
) {
    val title = vaultTitle(state)
    var confirmForget by remember(
        state.confirmationKey(),
        state.loading,
        state.biometricEnrolled,
        state.biometricNeedsForget,
    ) { mutableStateOf(false) }
    var createFolderDialogVisible by remember(state.lockRevision) { mutableStateOf(false) }
    var offlineActionsVisible by remember(state.lockRevision) { mutableStateOf(false) }
    val safeCallbacks =
        callbacks.copy(
            onForgetBiometric = { confirmForget = true },
            onShowOfflineActions = { offlineActionsVisible = true },
        )
    Box(modifier = modifier) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                VaultTopBar(title, state, safeCallbacks, accountId)
            },
            snackbarHost = { SnackbarHost(uploadSnackbar) },
            bottomBar = {
                if (state.destinationPickerPath == null) VaultPageNavigation(state, callbacks)
            },
            floatingActionButton = {
                if (state.destinationPickerPath == null) {
                    VaultFloatingActions(state, callbacks, onCreateFolder = { createFolderDialogVisible = true })
                }
            },
        ) { padding ->
            Column(
                modifier =
                    Modifier.fillMaxSize().padding(padding).then(
                        if (state.mode == VaultRouteMode.CONTENTS) {
                            Modifier
                        } else {
                            Modifier.padding(OpenCloudDimensions.SpacingMd)
                        },
                    ),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                VaultStatus(state, safeCallbacks)
                VaultModeContent(
                    state,
                    safeCallbacks,
                    Modifier.weight(1f),
                    createFolderDialogVisible,
                    onDismissCreateFolderDialog = { createFolderDialogVisible = false },
                )
            }
        }
        if (offlineActionsVisible) {
            VaultOfflineActionsDialog(
                offline = state.offline,
                onDismiss = { offlineActionsVisible = false },
                onRemove = callbacks.onRemoveOffline,
                onKeep = callbacks.onKeepDirectoryOffline,
            )
        }
        state.preview?.let {
            VaultPreviewDialog(
                preview = it,
                saving = state.previewSaving,
                saveError = state.previewSaveError,
                onSaveText = callbacks.onSavePreviewText,
                onSaveRange = callbacks.onSavePreviewTextRange,
                onOpenWith = callbacks.onOpenWithPreview,
                onDismiss = callbacks.onDismissPreview,
            )
        }
        if (state.biometricOfferPending && !state.loading) {
            AlertDialog(
                onDismissRequest = callbacks.onDeclineBiometricOffer,
                title = {
                    Text(
                        stringResource(
                            if (state.phoneRememberOffer) {
                                R.string.vault_phone_remember_offer_title
                            } else {
                                R.string.vault_biometric_offer_title
                            },
                        ),
                    )
                },
                text = {
                    Text(
                        stringResource(
                            if (state.phoneRememberOffer) {
                                R.string.vault_phone_remember_offer_message
                            } else {
                                R.string.vault_biometric_offer_message
                            },
                        ),
                    )
                },
                confirmButton = {
                    TextButton(
                        onClick =
                            if (state.phoneRememberOffer) {
                                callbacks.onRememberOnPhone
                            } else {
                                callbacks.onAcceptBiometricOffer
                            },
                    ) {
                        Text(
                            stringResource(
                                if (state.phoneRememberOffer) {
                                    R.string.vault_phone_remember_offer_accept
                                } else {
                                    R.string.vault_biometric_offer_accept
                                },
                            ),
                        )
                    }
                },
                dismissButton = {
                    TextButton(onClick = callbacks.onDeclineBiometricOffer) {
                        Text(
                            stringResource(
                                if (state.phoneRememberOffer) {
                                    R.string.vault_phone_remember_offer_decline
                                } else {
                                    R.string.vault_biometric_offer_decline
                                },
                            ),
                        )
                    }
                },
                properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            )
        }
        val hasRememberedAccess = state.biometricEnrolled || state.biometricNeedsForget
        if (confirmForget && hasRememberedAccess && !state.loading) {
            AlertDialog(
                onDismissRequest = { confirmForget = false },
                title = { Text(stringResource(R.string.vault_biometric_remove_title)) },
                text = { Text(stringResource(R.string.vault_biometric_remove_message)) },
                confirmButton = {
                    TextButton(
                        onClick = {
                            confirmForget = false
                            callbacks.onForgetBiometric()
                        },
                    ) { Text(stringResource(R.string.vault_biometric_remove_action)) }
                },
                dismissButton = {
                    TextButton(onClick = { confirmForget = false }) {
                        Text(stringResource(R.string.vault_biometric_keep_action))
                    }
                },
                properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            )
        }
        if (state.mode == VaultRouteMode.CONTENTS) {
            state.transferConflict?.let { conflict ->
                FileNameConflictDialog(
                    name = conflict.name,
                    proposedName = conflict.proposedName,
                    busy = state.loading,
                    secureWindow = true,
                    onKeepBoth = { callbacks.onResolveTransferConflict(true) },
                    onCancel = { callbacks.onResolveTransferConflict(false) },
                )
            }
        }
        if (state.rootActionsVisible && state.mode == VaultRouteMode.CONTENTS && !state.biometricOfferPending) {
            EncryptedRootActionsContent(state, callbacks)
        }
    }
}

@Composable
private fun vaultTitle(state: VaultRouteState): String =
    when (state.mode) {
        VaultRouteMode.CATALOG -> stringResource(R.string.vault_title)
        VaultRouteMode.DISCOVERY -> state.browseTitle ?: stringResource(R.string.vault_title)
        VaultRouteMode.UNLOCK ->
            state.selectedTitle?.let { stringResource(R.string.vault_unlock_title, it) }
                ?: stringResource(R.string.vault_title)
        VaultRouteMode.CONTENTS -> state.selectedTitle ?: stringResource(R.string.vault_title)
    }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VaultTopBar(
    title: String,
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    accountId: String?,
) {
    val accountDescription =
        accountId?.let {
            eu.opencloud.android.next.core.ui
                .accountIdentityDescription(it)
        }
    TopAppBar(
        modifier = Modifier.semantics { accountDescription?.let { contentDescription = it } },
        title = { Text(title) },
        navigationIcon = {
            IconButton(onClick = callbacks.onNavigateBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.vault_back))
            }
        },
        actions = {
            if (state.mode == VaultRouteMode.CONTENTS) {
                if (!state.offline) {
                    IconButton(
                        onClick = callbacks.onShowRootActions,
                        enabled =
                            state.currentPath.isEmpty() &&
                                !state.loading &&
                                !state.biometricOfferPending,
                    ) {
                        Icon(Icons.Default.Edit, stringResource(R.string.vault_edit_location))
                    }
                }
                IconButton(onClick = callbacks.onRetry) {
                    Icon(Icons.Filled.Refresh, stringResource(R.string.vault_refresh))
                }
                IconButton(onClick = callbacks.onLock) {
                    Icon(Icons.Filled.Lock, contentDescription = stringResource(R.string.vault_lock_action))
                }
            }
        },
    )
}

@Composable
private fun VaultStatus(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        state.error?.let { error ->
            Text(stringResource(error.stringRes), color = MaterialTheme.colorScheme.error)
            if (error == VaultRouteError.BIOMETRIC_SETUP) {
                state.biometricDiagnostic?.let { code ->
                    Text(stringResource(R.string.vault_biometric_diagnostic, code))
                }
            }
            if (error.retryable) TextButton(onClick = callbacks.onRetry) { Text(stringResource(R.string.vault_retry)) }
        }
        VaultLoadingStatus(state)
        PhoneSessionNotice(state)
    }
}

@Composable
private fun VaultLoadingStatus(state: VaultRouteState) {
    val message = state.statusLoadingMessage() ?: return
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        CircularProgressIndicator()
        Text(stringResource(message))
    }
}

private fun VaultRouteState.statusLoadingMessage(): Int? =
    if (!loading || mode == VaultRouteMode.UNLOCK) {
        null
    } else {
        when (mode) {
            VaultRouteMode.CATALOG -> R.string.vault_catalog_loading
            VaultRouteMode.DISCOVERY -> R.string.vault_discovery_loading
            VaultRouteMode.UNLOCK -> null
            VaultRouteMode.CONTENTS ->
                if (preparingUpload) {
                    R.string.vault_background_upload_preparing
                } else {
                    R.string.vault_contents_loading
                }
        }
    }

@Composable
private fun PhoneSessionNotice(state: VaultRouteState) {
    if (state.loading || (state.mode != VaultRouteMode.UNLOCK && state.mode != VaultRouteMode.CONTENTS)) return
    val code =
        when (state.phoneSessionIssueCode) {
            "US1", "US2", "US3", "US4", "US5", "US6", "US7" -> state.phoneSessionIssueCode
            else -> null
        } ?: return
    Text(
        stringResource(R.string.vault_phone_session_issue, code),
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

@Composable
private fun VaultModeContent(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    modifier: Modifier = Modifier,
    createFolderDialogVisible: Boolean = false,
    onDismissCreateFolderDialog: () -> Unit = {},
) {
    when (state.mode) {
        VaultRouteMode.CATALOG -> CatalogContent(state, callbacks, modifier)
        VaultRouteMode.DISCOVERY -> DiscoveryContent(state, callbacks, modifier)
        VaultRouteMode.UNLOCK -> UnlockContent(state, callbacks, modifier)
        VaultRouteMode.CONTENTS ->
            EncryptedBrowserContent(
                state,
                callbacks,
                createFolderDialogVisible,
                onDismissCreateFolderDialog,
                modifier,
            )
    }
}

@Composable
private fun CatalogContent(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        TextButton(onClick = callbacks.onShowOffline) { Text(stringResource(R.string.vault_offline_copies)) }
        if (state.offlineCatalog) Text(stringResource(R.string.vault_offline_explanation))
        if (!state.loading && state.error == null && state.locations.isEmpty()) {
            Text(stringResource(R.string.vault_catalog_empty))
            TextButton(onClick = callbacks.onRetry) { Text(stringResource(R.string.vault_retry)) }
        }
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        ) {
            items(state.locations, key = { it.id }) { location ->
                ListItem(
                    headlineContent = { Text(location.title) },
                    supportingContent = {
                        Text(
                            stringResource(
                                if (location.offline) R.string.vault_offline_copy else location.kind.stringRes,
                            ),
                        )
                    },
                    leadingContent = {
                        Icon(
                            if (location.isVaultRoot) Icons.Filled.Lock else Icons.Filled.Folder,
                            contentDescription = null,
                        )
                    },
                    modifier = Modifier.clickable(enabled = !state.loading) { callbacks.onSelectLocation(location.id) },
                )
            }
        }
    }
}

@Composable
private fun DiscoveryContent(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier) {
        if (!state.loading && state.error == null && state.entries.isEmpty()) {
            Text(stringResource(R.string.vault_discovery_empty))
        }
        LazyColumn(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        ) {
            items(state.entries, key = { it.id }) { entry ->
                ListItem(
                    headlineContent = { Text(entry.name) },
                    supportingContent = { if (entry.isVaultRoot) Text(stringResource(R.string.vault_folder)) },
                    leadingContent = {
                        Icon(
                            if (entry.isVaultRoot) Icons.Filled.Lock else Icons.Filled.Folder,
                            contentDescription = null,
                        )
                    },
                    modifier =
                        Modifier.clickable(enabled = !state.loading) {
                            if (entry.isVaultRoot) {
                                callbacks.onSelectVaultFolder(entry.id)
                            } else {
                                callbacks.onOpenDiscoveryFolder(entry.id)
                            }
                        },
                )
            }
        }
    }
}

private fun Context.findComponentActivity(): ComponentActivity {
    var current = this
    while (current is ContextWrapper) {
        if (current is ComponentActivity) return current
        current = current.baseContext
    }
    error("Vault screens require an activity context.")
}

@Composable
internal fun VaultPageNavigation(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
) {
    if (state.mode != VaultRouteMode.CONTENTS) return
    val picking = state.destinationPickerPath != null
    val page = if (picking) state.destinationPickerPage else state.directoryPage
    page?.takeIf { it.hasPrevious || it.hasNext }?.let {
        val loading = state.loading || picking && state.destinationPickerLoading
        eu.opencloud.android.next.core.ui.BrowserPageNavigation(
            eu.opencloud.android.next.core.ui.BrowserPageNavigationState(
                if (it.total == 0L) 0 else it.offset + 1,
                it.offset + it.count,
                it.total,
                !loading && it.hasPrevious,
                !loading && it.hasNext,
            ),
            if (picking) callbacks.onDestinationPage else callbacks.onDirectoryPage,
        )
    }
}

@Composable
private fun VaultFloatingActions(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    onCreateFolder: () -> Unit,
) {
    var addActionsExpanded by remember(state.lockRevision, state.destinationPickerPath) { mutableStateOf(false) }
    if (state.mode == VaultRouteMode.CONTENTS && !state.offline && state.destinationPickerPath == null) {
        Column(
            horizontalAlignment = Alignment.End,
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            if (addActionsExpanded && !state.loading) {
                val uploadLabel = stringResource(FilesR.string.browser_upload_file)
                ExtendedFloatingActionButton(
                    onClick = {
                        if (!state.loading) {
                            addActionsExpanded = false
                            callbacks.onUpload()
                        }
                    },
                    icon = { Icon(Icons.Default.CloudUpload, null) },
                    text = { Text(uploadLabel) },
                    modifier =
                        Modifier.semantics(mergeDescendants = true) {
                            contentDescription = uploadLabel
                        },
                )
                val scanLabel = stringResource(FilesR.string.browser_scan)
                ExtendedFloatingActionButton(
                    onClick = {
                        addActionsExpanded = false
                        callbacks.onScan()
                    },
                    icon = { Icon(Icons.Default.CameraAlt, null) },
                    text = { Text(scanLabel) },
                    modifier = Modifier.semantics(mergeDescendants = true) { contentDescription = scanLabel },
                )
                val createFolderLabel = stringResource(FilesR.string.browser_create_folder)
                ExtendedFloatingActionButton(
                    onClick = {
                        if (!state.loading) {
                            addActionsExpanded = false
                            onCreateFolder()
                        }
                    },
                    icon = { Icon(Icons.Default.Folder, null) },
                    text = { Text(createFolderLabel) },
                    modifier =
                        Modifier.semantics(mergeDescendants = true) {
                            contentDescription = createFolderLabel
                        },
                )
            }
            FloatingActionButton(
                onClick = { if (!state.loading) addActionsExpanded = !addActionsExpanded },
            ) {
                Icon(
                    if (addActionsExpanded) Icons.Default.Close else Icons.Default.Add,
                    contentDescription =
                        stringResource(
                            if (addActionsExpanded) {
                                FilesR.string.browser_close_new_actions
                            } else {
                                FilesR.string.browser_new
                            },
                        ),
                )
            }
        }
    }
}

@Composable
private fun VaultOfflineActionsDialog(
    offline: Boolean,
    onDismiss: () -> Unit,
    onRemove: () -> Unit,
    onKeep: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = { onDismiss() },
        title = {
            Text(
                stringResource(
                    if (offline) R.string.vault_remove_offline else R.string.vault_keep_offline,
                ),
            )
        },
        text = {
            Text(
                stringResource(
                    if (offline) {
                        R.string.vault_remove_offline_warning
                    } else {
                        R.string.vault_keep_offline_warning
                    },
                ),
            )
        },
        confirmButton = {
            TextButton(onClick = {
                onDismiss()
                if (offline) onRemove() else onKeep()
            }) { Text(stringResource(R.string.vault_confirm)) }
        },
        dismissButton = {
            TextButton(
                onClick = { onDismiss() },
            ) { Text(stringResource(R.string.vault_cancel)) }
        },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
    )
}

/** Returns true when Back belongs to the in-browser destination selection. */
@Suppress("ViewModelForwarding") // This route navigation helper invokes only destination navigation actions.
private fun navigateVaultDestinationBack(
    state: VaultRouteState,
    viewModel: VaultViewModel,
): Boolean {
    val destination = state.destinationPickerPath ?: return false
    if (!state.loading && !state.destinationPickerLoading) {
        if (destination.isEmpty()) {
            viewModel.dismissDestinationPicker()
        } else {
            viewModel.loadDestinationFolders(destination.substringBeforeLast('/', ""))
        }
    }
    return true
}
