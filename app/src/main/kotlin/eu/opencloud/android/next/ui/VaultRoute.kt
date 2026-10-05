package eu.opencloud.android.next.ui

import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.DocumentScanner
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Upload
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.window.Dialog
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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

// The route owns the model; only its lifecycle and prompt controller receive it. UI content is state-hoisted.
@Suppress("ViewModelForwarding", "LongParameterList", "LongMethod")
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
            onUp = vaultViewModel::up,
            onLock = ::lockVault,
            onRetry = vaultViewModel::retry,
            onAcceptBiometricOffer = {
                vaultViewModel.acceptBiometricOffer()
                prompts.showEnrollment(state.selectedTitle.orEmpty())
            },
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
        VaultScreen(state, callbacks)
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
            viewModel.lock()
        }
        val observer =
            LifecycleEventObserver { _, event ->
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

private fun navigateVaultBack(
    state: VaultRouteState,
    viewModel: VaultViewModel,
    onNavigateBack: () -> Unit,
) {
    when {
        state.preview != null -> viewModel.dismissPreview()
        state.mode == VaultRouteMode.DISCOVERY && state.currentPath.isNotEmpty() -> viewModel.up()
        state.mode == VaultRouteMode.DISCOVERY -> viewModel.showCatalog()
        state.mode == VaultRouteMode.CONTENTS && state.currentPath.isNotEmpty() -> viewModel.up()
        state.mode == VaultRouteMode.CONTENTS -> viewModel.lock()
        state.mode == VaultRouteMode.UNLOCK -> viewModel.showCatalog()
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

private class VaultPromptController(
    private val activity: ComponentActivity,
    private val viewModel: VaultViewModel,
) {
    private var activePrompt: BiometricPrompt? = null
    private var cancelPending: (() -> Unit)? = null
    private var generation = 0L

    fun cancel() {
        generation += 1
        val prompt = activePrompt
        val cancelOperation = cancelPending
        activePrompt = null
        cancelPending = null
        runCatching { prompt?.cancelAuthentication() }
        cancelOperation?.invoke()
    }

    fun showUnlock(title: String) {
        cancel()
        if (!hardwareAvailable()) return unavailable()
        val cipher = viewModel.prepareBiometricUnlock() ?: return
        startPrompt(title, cipher, viewModel::cancelBiometricUnlock, viewModel::completeBiometricUnlock)
    }

    fun showEnrollment(title: String) {
        cancel()
        if (!hardwareAvailable()) return unavailable()
        val cipher = viewModel.prepareBiometricEnrollment() ?: return
        startPrompt(title, cipher, viewModel::cancelBiometricEnrollment, viewModel::completeBiometricEnrollment)
    }

    private fun startPrompt(
        title: String,
        cipher: Cipher,
        cancelOperation: () -> Unit,
        complete: (Cipher?) -> Unit,
    ) {
        cancelPending = cancelOperation
        val requestGeneration = ++generation
        try {
            val prompt =
                biometricPrompt(
                    activity,
                    { result ->
                        if (generation == requestGeneration) {
                            generation += 1
                            activePrompt = null
                            cancelPending = null
                            complete(result.cryptoObject?.cipher)
                        }
                    },
                    {
                        if (generation == requestGeneration) {
                            generation += 1
                            activePrompt = null
                            cancelPending = null
                            cancelOperation()
                        }
                    },
                )
            activePrompt = prompt
            prompt.authenticate(
                biometricPromptInfo(
                    title = activity.getString(R.string.vault_biometric_title, title),
                    subtitle = activity.getString(R.string.vault_biometric_subtitle),
                    negativeButton = activity.getString(R.string.vault_biometric_cancel),
                ),
                BiometricPrompt.CryptoObject(cipher),
            )
        } catch (_: RuntimeException) {
            if (generation == requestGeneration) {
                cancel()
                unavailable()
            }
        }
    }

    private fun hardwareAvailable(): Boolean =
        runCatching {
            BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
        }.getOrDefault(false)

    private fun unavailable() {
        Toast.makeText(activity, R.string.vault_biometric_unavailable, Toast.LENGTH_SHORT).show()
    }
}

/** Hoisted route content for UI tests and previews. Password and preview state are never saveable. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("CyclomaticComplexMethod", "LongMethod") // Mode, prompts and independently visible secure overlays.
fun VaultScreen(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    modifier: Modifier = Modifier,
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
            topBar = { VaultTopBar(title, state, safeCallbacks) },
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
                onOpenWith = callbacks.onOpenWithPreview,
                onDismiss = callbacks.onDismissPreview,
            )
        }
        if (state.biometricOfferPending && !state.loading) {
            AlertDialog(
                onDismissRequest = callbacks.onDeclineBiometricOffer,
                title = { Text(stringResource(R.string.vault_biometric_offer_title)) },
                text = { Text(stringResource(R.string.vault_biometric_offer_message)) },
                confirmButton = {
                    TextButton(onClick = callbacks.onAcceptBiometricOffer) {
                        Text(stringResource(R.string.vault_biometric_offer_accept))
                    }
                },
                dismissButton = {
                    TextButton(onClick = callbacks.onDeclineBiometricOffer) {
                        Text(stringResource(R.string.vault_biometric_offer_decline))
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
) {
    TopAppBar(
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
        if (state.loading) {
            CircularProgressIndicator()
            val message =
                when (state.mode) {
                    VaultRouteMode.CATALOG -> R.string.vault_catalog_loading
                    VaultRouteMode.DISCOVERY -> R.string.vault_discovery_loading
                    VaultRouteMode.UNLOCK -> R.string.vault_unlocking
                    VaultRouteMode.CONTENTS -> R.string.vault_contents_loading
                }
            Text(stringResource(message))
        }
    }
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
private fun UnlockContent(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    modifier: Modifier = Modifier,
) {
    var password by remember(state.selectedLocation?.id, state.mode, state.lockRevision) { mutableStateOf("") }
    var passwordVisible by remember(
        state.selectedLocation?.id,
        state.mode,
        state.lockRevision,
    ) { mutableStateOf(false) }
    Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text(stringResource(R.string.vault_password_label)) },
            singleLine = true,
            visualTransformation = if (passwordVisible) VisualTransformation.None else PasswordVisualTransformation(),
            trailingIcon = {
                IconButton(onClick = { passwordVisible = !passwordVisible }, enabled = !state.loading) {
                    Icon(
                        if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        stringResource(
                            if (passwordVisible) R.string.vault_hide_password else R.string.vault_show_password,
                        ),
                    )
                }
            },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            enabled = !state.loading,
            modifier = Modifier.fillMaxWidth(),
        )
        FlowRow(
            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        ) {
            Button(
                enabled = !state.loading && password.isNotEmpty(),
                onClick = {
                    val suppliedPassword = password.toCharArray()
                    password = ""
                    passwordVisible = false
                    callbacks.onUnlock(suppliedPassword)
                },
            ) { Text(stringResource(R.string.vault_unlock_action)) }
            if (state.biometricEnrolled) {
                TextButton(onClick = callbacks.onBiometricUnlock, enabled = !state.loading) {
                    Text(stringResource(R.string.vault_biometric_unlock))
                }
            }
            if (state.biometricEnrolled || state.biometricNeedsForget) {
                TextButton(onClick = callbacks.onForgetBiometric, enabled = !state.loading) {
                    Text(stringResource(R.string.vault_biometric_forget))
                }
            }
        }
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

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Secure preview state and independent reader/editor actions.
private fun VaultPreviewDialog(
    preview: VaultRoutePreview,
    saving: Boolean,
    saveError: VaultRouteError?,
    onSaveText: (VaultRoutePreview, ByteArray) -> Unit,
    onOpenWith: () -> Unit,
    onDismiss: () -> Unit,
) {
    if (preview.kind == VaultPreviewKind.TEXT) {
        EncryptedTextPreviewDialog(preview, saving, saveError, onSaveText, onDismiss, onOpenWith)
        return
    }
    BackHandler(onBack = onDismiss)
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn, usePlatformDefaultWidth = false),
    ) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            topBar = {
                TopAppBar(
                    title = { Text(preview.title, maxLines = 1) },
                    actions = {
                        TextButton(onClick = onOpenWith) { Text(stringResource(R.string.vault_open_with)) }
                    },
                    navigationIcon = {
                        IconButton(onClick = onDismiss) {
                            Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.vault_close))
                        }
                    },
                )
            },
        ) { padding ->
            Box(
                Modifier.fillMaxSize().padding(padding).padding(OpenCloudDimensions.SpacingMd),
                contentAlignment = Alignment.Center,
            ) {
                when (preview.kind) {
                    VaultPreviewKind.IMAGE -> {
                        val owner = remember(preview.bytes) { OwnedBitmap() }
                        DisposableEffect(owner) { onDispose { owner.close() } }
                        var decoded by remember(owner) { mutableStateOf(DecodedBitmap(false, null)) }
                        LaunchedEffect(owner) {
                            val copy = preview.bytes.copyOf()
                            var bitmap: Bitmap? = null
                            try {
                                // Cancellation may discard withContext's result on its return dispatch.
                                withContext(Dispatchers.Default) { bitmap = decodeBoundedBitmap(copy) }
                                currentCoroutineContext().ensureActive()
                                val ready = bitmap
                                if (ready != null && !owner.adopt(ready)) return@LaunchedEffect
                                bitmap = null
                                decoded = DecodedBitmap(true, ready)
                            } finally {
                                bitmap?.recycle()
                                copy.fill(0)
                            }
                        }
                        if (!decoded.complete) {
                            CircularProgressIndicator()
                        } else if (decoded.bitmap == null) {
                            Text(stringResource(R.string.vault_preview_unavailable))
                        } else {
                            VaultPreviewImage(requireNotNull(decoded.bitmap), preview.title)
                        }
                    }
                    VaultPreviewKind.PDF -> EncryptedPdfPreview(preview.bytes)
                    else -> Text(stringResource(R.string.vault_preview_unavailable))
                }
            }
        }
    }
}

@Composable
private fun VaultPreviewImage(
    bitmap: Bitmap,
    title: String,
) {
    var scale by remember(bitmap) { mutableFloatStateOf(1f) }
    var offset by remember(bitmap) { mutableStateOf(Offset.Zero) }
    val transform =
        rememberTransformableState { zoom, pan, _ ->
            scale = (scale * zoom).coerceIn(1f, 5f)
            offset = if (scale == 1f) Offset.Zero else offset + pan
        }
    Box(Modifier.fillMaxSize().clipToBounds().transformable(transform), contentAlignment = Alignment.Center) {
        Image(
            bitmap.asImageBitmap(),
            title,
            Modifier.fillMaxSize().graphicsLayer {
                scaleX = scale
                scaleY = scale
                translationX = offset.x
                translationY = offset.y
            },
        )
    }
}

internal fun decodeBoundedBitmap(
    bytes: ByteArray,
    maximumDimension: Int = MAX_IMAGE_DIMENSION,
): Bitmap? {
    var bitmap: Bitmap? = null
    if (bytes.size <= MAX_IMAGE_PREVIEW_BYTES) {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth > 0 &&
            bounds.outHeight > 0 &&
            bounds.outWidth.toLong() * bounds.outHeight <= MAX_IMAGE_PIXELS
        ) {
            var sample = 1
            while (bounds.outWidth / sample > maximumDimension ||
                bounds.outHeight / sample > maximumDimension ||
                bounds.outWidth.toLong() * bounds.outHeight / (sample.toLong() * sample) > MAX_DECODED_PIXELS
            ) {
                sample *= 2
            }
            bitmap =
                BitmapFactory.decodeByteArray(
                    bytes,
                    0,
                    bytes.size,
                    BitmapFactory.Options().apply {
                        inSampleSize = sample
                        inPreferredConfig = Bitmap.Config.ARGB_8888
                    },
                )
        }
    }
    return bitmap
}

private fun biometricPrompt(
    activity: ComponentActivity,
    onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    onError: () -> Unit,
): BiometricPrompt =
    BiometricPrompt(
        activity as androidx.fragment.app.FragmentActivity,
        ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess(result)

            override fun onAuthenticationError(
                errorCode: Int,
                errString: CharSequence,
            ) = onError()
        },
    )

private fun biometricPromptInfo(
    title: String,
    subtitle: String,
    negativeButton: String,
): BiometricPrompt.PromptInfo =
    BiometricPrompt.PromptInfo
        .Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setNegativeButtonText(negativeButton)
        .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()

private fun Context.findComponentActivity(): ComponentActivity {
    var current = this
    while (current is ContextWrapper) {
        if (current is ComponentActivity) return current
        current = current.baseContext
    }
    error("Vault screens require an activity context.")
}

private const val MAX_IMAGE_PREVIEW_BYTES = 8 * 1024 * 1024
private const val MAX_IMAGE_PIXELS = 100_000_000L
private const val MAX_DECODED_PIXELS = 4_194_304L
private const val MAX_IMAGE_DIMENSION = 2048

internal data class DecodedBitmap(
    val complete: Boolean,
    val bitmap: Bitmap?,
)

/** Transfers decoded bitmap ownership to the dialog before publishing it to Compose. */
internal class OwnedBitmap {
    private var bitmap: Bitmap? = null
    private var closed = false

    fun adopt(value: Bitmap): Boolean {
        if (closed) return false
        check(bitmap == null)
        bitmap = value
        return true
    }

    fun close() {
        closed = true
        bitmap?.recycle()
        bitmap = null
    }
}

enum class VaultRouteMode { CATALOG, DISCOVERY, UNLOCK, CONTENTS }

enum class VaultPreviewKind { TEXT, IMAGE, PDF, UNSUPPORTED }

enum class VaultRouteError(
    val stringRes: Int,
    val retryable: Boolean,
) {
    CATALOG(R.string.vault_catalog_error, true),
    SERVER_RESPONSE(R.string.vault_server_response_error, true),
    DISCOVERY(R.string.vault_discovery_error, true),
    UNLOCK(R.string.vault_unlock_error, false),
    CONNECTION(R.string.vault_connection_error, true),
    SECURE_CONNECTION(R.string.vault_secure_connection_error, false),
    AUTHENTICATION(R.string.vault_authentication_error, false),
    ACCESS_DENIED(R.string.vault_access_denied_error, false),
    VAULT_CHANGED(R.string.vault_changed_error, false),
    UNLOCK_PROOF(R.string.vault_unlock_proof_error, false),
    CONTENTS(R.string.vault_contents_error, true),
    PREVIEW(R.string.vault_preview_error, false),
    BIOMETRIC(R.string.vault_biometric_unavailable, false),
    BIOMETRIC_SETUP(R.string.vault_biometric_setup_error, false),
    OPERATION(R.string.vault_operation_failed, false),
    TRANSFER_UNLOCK_REQUIRED(R.string.vault_unlock_to_finish, false),
    EXPORT_FAILED(R.string.vault_export_failed, false),
    BIOMETRIC_CLEANUP(R.string.vault_biometric_cleanup_error, true),
}

data class VaultRouteLocation(
    val id: String,
    val title: String,
    val kind: VaultLocationKindUi,
    val isVaultRoot: Boolean,
    val offline: Boolean = false,
)

enum class VaultLocationKindUi(
    val stringRes: Int,
) {
    FOLDER_VAULT(R.string.vault_folder),
    SPACE_VAULT(R.string.vault_space),
    PERSONAL(R.string.vault_personal_files),
    SPACE(R.string.vault_space),
}

data class VaultRouteEntry(
    val id: String,
    val name: String,
    val path: String,
    val isFolder: Boolean,
    val isVaultRoot: Boolean,
    val size: Long,
    val contentType: String?,
    val offlineAvailable: Boolean? = null,
    val displaySize: Long? = size,
)

data class VaultRoutePreview(
    val title: String,
    val bytes: ByteArray,
    val kind: VaultPreviewKind,
    val editable: Boolean = false,
)

data class VaultRouteState(
    val mode: VaultRouteMode = VaultRouteMode.CATALOG,
    val locations: List<VaultRouteLocation> = emptyList(),
    val entries: List<VaultRouteEntry> = emptyList(),
    val selectedLocation: VaultRouteLocation? = null,
    val selectedTitle: String? = null,
    val browseTitle: String? = null,
    val currentPath: String = "",
    val loading: Boolean = false,
    val error: VaultRouteError? = null,
    val biometricDiagnostic: String? = null,
    val biometricEnrolled: Boolean = false,
    val biometricNeedsForget: Boolean = false,
    val canEnrollBiometric: Boolean = false,
    val biometricOfferPending: Boolean = false,
    val rootActionsVisible: Boolean = false,
    val offline: Boolean = false,
    val offlineCatalog: Boolean = false,
    val preview: VaultRoutePreview? = null,
    val previewSaving: Boolean = false,
    val previewSaveError: VaultRouteError? = null,
    val lockRevision: Long = 0,
    val transferConflict: VaultTransferConflict? = null,
    val destinationPickerPath: String? = null,
    val destinationPickerEntries: List<VaultRouteEntry> = emptyList(),
    val destinationPickerLoading: Boolean = false,
    val destinationPickerError: VaultRouteError? = null,
)

data class VaultRouteCallbacks(
    val onNavigateBack: () -> Unit,
    val onSelectLocation: (String) -> Unit,
    val onOpenDiscoveryFolder: (String) -> Unit,
    val onSelectVaultFolder: (String) -> Unit,
    val onUnlock: (CharArray) -> Unit,
    val onBiometricUnlock: () -> Unit,
    val onBiometricEnroll: () -> Unit,
    val onForgetBiometric: () -> Unit,
    val onOpenVaultFolder: (String) -> Unit,
    val onOpenPreview: (String) -> Unit,
    val onDismissPreview: () -> Unit,
    val onOpenWithPreview: () -> Unit = {},
    val onSavePreviewText: (VaultRoutePreview, ByteArray) -> Unit = { _, bytes -> bytes.fill(0) },
    val onLoadThumbnail: suspend (String) -> ByteArray? = { null },
    val onUp: () -> Unit,
    val onLock: () -> Unit,
    val onRetry: () -> Unit,
    val onResolveTransferConflict: (Boolean) -> Unit = {},
    val onLoadDestinationFolders: (String) -> Unit = {},
    val onDismissDestinationPicker: () -> Unit = {},
    val onShowOffline: () -> Unit = {},
    val onKeepDirectoryOffline: () -> Unit = {},
    val onRemoveOffline: () -> Unit = {},
    val onShowOfflineActions: () -> Unit = {},
    val onCreateFolder: (String) -> Unit = {},
    val onUpload: () -> Unit = {},
    val onScan: () -> Unit = {},
    val onEntryAction: (String, VaultEntryAction, String?) -> Unit = { _, _, _ -> },
    val onAcceptBiometricOffer: () -> Unit = {},
    val onDeclineBiometricOffer: () -> Unit = {},
    val onShowRootActions: () -> Unit = {},
    val onManageLocation: () -> Unit = {},
    val onDismissRootActions: () -> Unit = {},
    val onRenameRoot: (String) -> Unit = {},
    val onDeleteRoot: () -> Unit = {},
)

@Composable
private fun VaultFloatingActions(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    onCreateFolder: () -> Unit,
) {
    var addActionsExpanded by remember(state.lockRevision) { mutableStateOf(false) }
    if (state.mode == VaultRouteMode.CONTENTS && !state.offline) {
        Column(
            horizontalAlignment = Alignment.End,
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            if (addActionsExpanded && !state.loading) {
                val createFolderLabel = stringResource(R.string.vault_new_folder)
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
                val scanLabel = stringResource(R.string.vault_scan_document)
                ExtendedFloatingActionButton(
                    onClick = {
                        addActionsExpanded = false
                        callbacks.onScan()
                    },
                    icon = { Icon(Icons.Default.DocumentScanner, null) },
                    text = { Text(scanLabel) },
                    modifier = Modifier.semantics(mergeDescendants = true) { contentDescription = scanLabel },
                )
                val uploadLabel = stringResource(R.string.vault_upload_file)
                ExtendedFloatingActionButton(
                    onClick = {
                        if (!state.loading) {
                            addActionsExpanded = false
                            callbacks.onUpload()
                        }
                    },
                    icon = { Icon(Icons.Default.Upload, null) },
                    text = { Text(uploadLabel) },
                    modifier =
                        Modifier.semantics(mergeDescendants = true) {
                            contentDescription = uploadLabel
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
                                R.string.vault_close_actions
                            } else {
                                R.string.vault_new_actions
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

data class VaultTransferConflict(
    val sourceId: String,
    val name: String,
    val path: String,
    val action: VaultEntryAction,
    val proposedName: String,
)

/** Returns true when Back belongs to the in-browser destination selection. */
@Suppress("ViewModelForwarding") // This route navigation helper invokes only destination navigation actions.
private fun navigateVaultDestinationBack(state: VaultRouteState, viewModel: VaultViewModel): Boolean {
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
