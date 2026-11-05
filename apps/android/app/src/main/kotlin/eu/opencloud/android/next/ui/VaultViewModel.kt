package eu.opencloud.android.next.ui

import android.app.Application
import android.app.KeyguardManager
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultKeyStore
import eu.opencloud.android.next.core.sync.VaultExternalCopyLease
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.core.sync.VaultUnlockException
import eu.opencloud.android.next.core.sync.VaultUnlockFailure
import eu.opencloud.android.next.core.sync.asBoundaryEntry
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Cipher

@Suppress("LargeClass") // Coordinates route actions; VaultSessionLifecycle owns session and key admission.
class VaultViewModel internal constructor(
    application: Application,
    private val repository: VaultRouteRepository,
    private val biometricStore: VaultBiometricKeyStore,
    private val biometricPreferences: VaultOfferPreferences = AndroidVaultOfferPreferences(application),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val adapters: VaultViewModelAdapters = VaultViewModelAdapters(application),
) : AndroidViewModel(application) {
    constructor(application: Application) :
        this(
            application,
            AndroidVaultRouteRepository(application),
            AndroidVaultBiometricKeyStore(VaultKeyStore(application)),
            AndroidVaultOfferPreferences(application),
        )

    private val mutableState = kotlinx.coroutines.flow.MutableStateFlow(VaultRouteState())
    val state = mutableState.asStateFlow()

    private val accountId: String? get() = lifecycle.accountId
    private val routeActive: Boolean get() = lifecycle.routeActive
    private val generation: Long get() = lifecycle.generation
    private val session: VaultRouteSession? get() = lifecycle.session
    private val target: VaultSessionTarget? get() = lifecycle.target
    private val currentTargetIdentity: VaultIdentity? get() = lifecycle.currentTargetIdentity
    private var openRootMenuAfterUnlock = false
    private var catalogJob: Job? = null
    private var offlineCompletionJob: Job? = null
    private var showHidden = false
    private var pendingTransferSource: VaultFolder? = null
    private var currentSource: VaultLocation? = null
    private var discoveryReturn: DiscoveryReturn? = null
    private val presentedEntries = mutableMapOf<String, PresentedVaultFolder>()
    private var pendingTransfer: PendingVaultTransfer? = null
    private val pickerLease = VaultPickerLease()
    private var pickerTimeout: Job? = null
    private var pickerSuspended = false
    private val directoryContent =
        VaultDirectoryContent(
            mutableState,
            object : VaultDirectoryOwner {
                override fun showHidden(): Boolean = showHidden

                override fun isCurrent(
                    opened: VaultRouteSession,
                    token: Long,
                    account: String,
                ): Boolean = this@VaultViewModel.isCurrent(token, account) && session === opened

                override fun isRouteCurrent(
                    token: Long,
                    account: String,
                ): Boolean = this@VaultViewModel.isCurrent(token, account)

                override fun present(entries: List<VaultFolder>): List<VaultRouteEntry> = presentEntries(entries)

                override fun clearPresented() = presentedEntries.clear()

                override fun reportFailure(
                    failure: Exception,
                    token: Long,
                    account: String,
                ) {
                    this@VaultViewModel.reportFailure(
                        failure,
                        VaultRouteError.CONTENTS,
                        VaultFailureContext(token, account, lockOnRevocation = true),
                    )
                }
            },
        )
    private val pickedTransferExecution =
        VaultPickedTransferExecution(
            application,
            ioDispatcher,
            adapters.uploadPollReady,
            mutableState,
            object : VaultPickedTransferOwner {
                override fun isCurrent(
                    opened: VaultRouteSession,
                    token: Long,
                    account: String,
                ): Boolean = this@VaultViewModel.isCurrent(token, account) && session === opened

                override fun isCurrentTransferSession(
                    opened: VaultRouteSession,
                    identity: VaultIdentity,
                    token: Long,
                    account: String,
                ): Boolean = this@VaultViewModel.isCurrentTransferSession(opened, identity, token, account)

                override suspend fun verifyUploadDirectory(
                    opened: VaultRouteSession,
                    path: String,
                ) = this@VaultViewModel.verifyUploadDirectory(opened, path)

                override suspend fun revalidateExportSource(
                    opened: VaultRouteSession,
                    path: String,
                    request: PendingVaultTransfer.Export,
                ): VaultFolder = this@VaultViewModel.revalidateExportSource(opened, path, request)

                override suspend fun publishTransferListing(
                    opened: VaultRouteSession,
                    path: String,
                    token: Long,
                    account: String,
                ) = this@VaultViewModel.publishTransferListing(opened, path, token, account)
            },
        )
    private val previewContent =
        VaultPreviewContent(
            application,
            ioDispatcher,
            mutableState,
            object : VaultPreviewOwner {
                override fun isCurrent(request: VaultPreviewRequest): Boolean =
                    this@VaultViewModel.isCurrent(request.token, request.account) && session === request.session

                override fun backingAccessValid(request: VaultPreviewRequest): Boolean =
                    accountId == request.account && session === request.session && routeActive

                override fun isThumbnailCurrent(request: VaultThumbnailRequest): Boolean =
                    this@VaultViewModel.isThumbnailCurrent(request)

                override fun reportFailure(
                    request: VaultPreviewRequest,
                    failure: Exception,
                ) {
                    this@VaultViewModel.reportFailure(
                        failure,
                        VaultRouteError.PREVIEW,
                        VaultFailureContext(request.token, request.account, lockOnRevocation = true),
                    )
                }
            },
        )
    private val previewActions =
        VaultPreviewActions(
            application,
            ioDispatcher,
            viewModelScope,
            mutableState,
            previewContent,
            object : VaultPreviewActionOwner {
                override fun isCurrent(
                    opened: VaultRouteSession,
                    token: Long,
                    account: String,
                ): Boolean = this@VaultViewModel.isCurrent(token, account) && session === opened

                override fun nextGeneration(): Long = this@VaultViewModel.nextGeneration()

                override fun trackOperation(job: Job) = lifecycle.trackOperation(job)

                override suspend fun revalidateSource(
                    opened: VaultRouteSession,
                    expected: VaultFolder,
                ): VaultFolder = revalidateActionSource(opened, expected)

                override fun reloadContents(
                    opened: VaultRouteSession,
                    token: Long,
                    account: String,
                ) = loadContents(opened, mutableState.value.currentPath, token, account)

                override fun reportFailure(
                    failure: Exception,
                    fallback: VaultRouteError,
                    context: VaultFailureContext,
                ) = this@VaultViewModel.reportFailure(failure, fallback, context)
            },
        )
    private val destinationPicker =
        VaultDestinationPicker(
            viewModelScope,
            mutableState,
            object : VaultDestinationOwner {
                override fun capture(): VaultDestinationOwnerSnapshot? = destinationOwnerSnapshot()

                override fun isCurrent(owner: VaultDestinationOwnerSnapshot): Boolean {
                    val sessionCurrent = routeActive && session === owner.opened && accountId == owner.account
                    val viewCurrent =
                        generation == owner.routeGeneration && mutableState.value.lockRevision == owner.lockRevision
                    return sessionCurrent && viewCurrent
                }

                override fun closeContents() = closeDirectory()

                override fun reportFailure(
                    owner: VaultDestinationOwnerSnapshot,
                    failure: Exception,
                ) {
                    reportDestinationFailure(owner, failure)
                }
            },
        )

    private val lifecycle: VaultSessionLifecycle =
        VaultSessionLifecycle(
            application,
            repository,
            biometricStore,
            biometricPreferences,
            ioDispatcher,
            adapters.deviceRemember,
            viewModelScope,
            mutableState,
            directoryContent,
            object : VaultSessionPresentation {
                override fun invalidateRoutePresentation() {
                    catalogJob?.cancel()
                    catalogJob = null
                    currentSource = null
                }

                override fun closeSessionContent() {
                    closeDirectory()
                    offlineCompletionJob?.cancel()
                    offlineCompletionJob = null
                    clearDestinationPicker()
                    pickerTimeout?.cancel()
                    pickerTimeout = null
                    pickerLease.clear()
                    pickerSuspended = false
                }

                override fun clearSensitivePresentation() {
                    pendingTransferSource = null
                    mutableState.value = mutableState.value.copy(transferConflict = null)
                    clearPreview()
                    presentedEntries.clear()
                }

                override fun clearPreview() = this@VaultViewModel.clearPreview()

                override fun presentLocation(location: VaultLocation): VaultRouteLocation =
                    this@VaultViewModel.presentLocation(location)

                override fun presentEntries(entries: List<VaultFolder>): List<VaultRouteEntry> =
                    this@VaultViewModel.presentEntries(entries)

                override fun offersResolved() = maybeOpenRootActions()

                override suspend fun postOpen(
                    opened: VaultRouteSession,
                    token: Long,
                    account: String,
                ) {
                    processPendingTransfer(opened, token, account)
                    if (isCurrent(token, account) && session === opened) {
                        observePendingOffline(opened, account)
                    }
                }

                override fun reportFailure(
                    failure: Throwable,
                    fallback: VaultRouteError,
                    context: VaultFailureContext,
                ) = this@VaultViewModel.reportFailure(failure, fallback, context)
            },
        )

    private val rootManagement =
        VaultRootManagement(
            repository,
            viewModelScope,
            mutableState,
            lifecycle,
            object : VaultRootManagementPresentation {
                override fun presentLocation(location: VaultLocation): VaultRouteLocation =
                    this@VaultViewModel.presentLocation(location)

                override fun renamed(location: VaultLocation) {
                    directLocation = location
                }

                override fun showCatalog() = this@VaultViewModel.showCatalog()

                override fun reportFailure(
                    failure: Exception,
                    context: VaultFailureContext,
                ) = this@VaultViewModel.reportFailure(failure, VaultRouteError.OPERATION, context)
            },
        )

    fun enterRoute(
        accountId: String,
        initialLocation: VaultLocation? = null,
        openMenuAfterUnlock: Boolean = false,
        offlineCatalog: Boolean = false,
    ) {
        val sameTarget = directLocation == initialLocation && openRootMenuAfterUnlock == openMenuAfterUnlock
        if (routeActive && this.accountId == accountId && sameTarget) {
            return
        }
        leaveRoute()
        lifecycle.enter(accountId)
        directLocation = initialLocation
        openRootMenuAfterUnlock = openMenuAfterUnlock
        if (initialLocation == null) {
            if (offlineCatalog) showOfflineCatalog() else refreshCatalog()
        } else {
            selectDirectLocation(accountId, initialLocation)
        }
    }

    fun leaveRoute() {
        val phoneSessionIssueCode = mutableState.value.phoneSessionIssueCode
        lifecycle.leave()
        currentSource = null
        discoveryReturn = null
        sourceLocations = emptyMap()
        directLocation = null
        pendingTransfer = null
        lifecycle.clearTarget()
        mutableState.value =
            VaultRouteState(
                lockRevision = mutableState.value.lockRevision + 1,
                phoneSessionIssueCode = phoneSessionIssueCode,
            )
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    fun refreshCatalog() {
        loadCatalog(offlineOnly = false)
    }

    fun showOfflineCatalog() {
        discoveryReturn = null
        closeSession()
        lifecycle.clearTarget()
        currentSource = null
        loadCatalog(offlineOnly = true)
    }

    @Suppress("TooGenericExceptionCaught") // Repository boundaries map heterogeneous errors; cancellation is rethrown.
    private fun loadCatalog(offlineOnly: Boolean) {
        val account = accountId ?: return
        val token = nextGeneration()
        catalogJob?.cancel()
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        catalogJob =
            viewModelScope.launch {
                try {
                    val locations =
                        if (offlineOnly) {
                            repository.offlineLocations(
                                account,
                            )
                        } else {
                            repository.locations(account)
                        }
                    if (isCurrent(token, account)) {
                        val presented = locations.map(::presentLocation)
                        sourceLocations = locations.associateBy(::locationKey)
                        mutableState.value =
                            VaultRouteState(
                                locations = presented,
                                offlineCatalog = offlineOnly,
                                loading = false,
                                lockRevision = mutableState.value.lockRevision,
                            )
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        VaultRouteError.CATALOG,
                        VaultFailureContext(token, account, classifyVaultIdentity = false),
                    )
                }
            }
    }

    private var sourceLocations: Map<String, VaultLocation> = emptyMap()
    private var directLocation: VaultLocation? = null

    private fun selectDirectLocation(
        account: String,
        location: VaultLocation,
    ) {
        val isValidVaultRoot =
            location.isVaultRoot &&
                location.kind in setOf(VaultLocationKind.FOLDER_VAULT, VaultLocationKind.SPACE_VAULT) &&
                listOf(location.accountId, location.canonicalServer, location.driveId, location.remoteVaultId)
                    .all(String::isNotBlank)
        if (location.accountId != account || !isValidVaultRoot) {
            mutableState.value =
                VaultRouteState(
                    error = VaultRouteError.VAULT_CHANGED,
                    lockRevision = mutableState.value.lockRevision + 1,
                )
            return
        }
        val selected = VaultSessionTarget(location, location.vaultPath, location.title, location.remoteVaultId)
        lifecycle.selectTarget(selected)
        currentSource = null
        showPasswordUnlock(selected)
    }

    fun selectLocation(id: String) {
        val location = sourceLocations[id] ?: return
        discoveryReturn = null
        clearSensitiveState()
        currentSource = location
        if (location.isVaultRoot) {
            val selectedTarget =
                VaultSessionTarget(location, location.vaultPath, location.title, location.remoteVaultId)
            lifecycle.selectTarget(selectedTarget)
            showPasswordUnlock(selectedTarget)
        } else {
            lifecycle.clearTarget()
            val token = nextGeneration()
            mutableState.value =
                mutableState.value.copy(
                    mode = VaultRouteMode.DISCOVERY,
                    selectedLocation = presentLocation(location),
                    selectedTitle = null,
                    browseTitle = location.title,
                    currentPath = "",
                    entries = emptyList(),
                    loading = true,
                    error = null,
                    biometricEnrolled = false,
                    biometricNeedsForget = false,
                    canEnrollBiometric = false,
                    biometricOfferPending = false,
                    phoneRememberOffer = false,
                    lockRevision = mutableState.value.lockRevision + 1,
                )
            loadDiscovery(location, "", token)
        }
    }

    fun openDiscoveryFolder(id: String) {
        val entry = findEntry(id)?.route?.takeIf { it.isFolder && !it.isVaultRoot } ?: return
        val source = currentSource ?: return
        val token = nextGeneration()
        mutableState.value =
            mutableState.value.copy(currentPath = entry.path, browseTitle = entry.name, loading = true, error = null)
        loadDiscovery(source, entry.path, token)
    }

    fun selectVaultFolder(id: String) {
        val presented = findEntry(id)?.takeIf { it.route.isVaultRoot && it.route.isFolder } ?: return
        val entry = presented.route
        val source = currentSource ?: return
        val folderLocation =
            source.copy(
                title = entry.name,
                kind = VaultLocationKind.FOLDER_VAULT,
                remoteVaultId = presented.remote.id,
                vaultPath = entry.path,
                isVaultRoot = true,
            )
        discoveryReturn = DiscoveryReturn(source, mutableState.value.currentPath, mutableState.value.browseTitle)
        val selectedTarget = VaultSessionTarget(folderLocation, entry.path, entry.name, presented.remote.id)
        lifecycle.selectTarget(selectedTarget)
        showPasswordUnlock(selectedTarget)
    }

    fun showCatalog() {
        discoveryReturn = null
        invalidateRequests()
        clearSensitiveState()
        currentSource = null
        lifecycle.clearTarget()
        mutableState.value =
            mutableState.value.copy(
                mode = VaultRouteMode.CATALOG,
                preview = null,
                rootActionsVisible = false,
                selectedLocation = null,
                selectedTitle = null,
                browseTitle = null,
                currentPath = "",
                entries = emptyList(),
                loading = false,
                error = null,
                biometricEnrolled = false,
                biometricNeedsForget = false,
                canEnrollBiometric = false,
                biometricOfferPending = false,
                phoneRememberOffer = false,
                lockRevision = mutableState.value.lockRevision + 1,
            )
    }

    /** Restore the previous browser and close route secrets; the phone-unlock cache follows its own policy. */
    fun returnFromVault() {
        val origin = discoveryReturn
        showCatalog()
        if (origin == null) return
        currentSource = origin.location
        val token = nextGeneration()
        mutableState.value =
            mutableState.value.copy(
                mode = VaultRouteMode.DISCOVERY,
                selectedLocation = presentLocation(origin.location),
                browseTitle = origin.title,
                currentPath = origin.path,
                loading = true,
            )
        loadDiscovery(origin.location, origin.path, token)
    }

    private data class DiscoveryReturn(
        val location: VaultLocation,
        val path: String,
        val title: String?,
    )

    private fun observePendingOffline(
        opened: VaultRouteSession,
        account: String,
    ) {
        offlineCompletionJob?.cancel()
        offlineCompletionJob =
            viewModelScope.launch {
                // Completed publication receipts can outlive both their journal and transfer history.
                // Recover once on every unlock even when no AWAITING_UNLOCK row emits an event.
                if (routeActive && accountId == account && session === opened) {
                    completePendingOffline(opened, account)
                }
                opened
                    .observePendingOffline()
                    .catch { failure ->
                        reportOfflineFailure(opened, account, generation, failure)
                    }.collect {
                        if (routeActive && accountId == account && session === opened) {
                            completePendingOffline(opened, account)
                        }
                    }
            }
    }

    // Repository failures become safe UI errors; cancellation must propagate.
    @Suppress("TooGenericExceptionCaught")
    private suspend fun completePendingOffline(
        opened: VaultRouteSession,
        account: String,
    ) {
        val token = generation
        try {
            opened.completePendingOffline()
            if (isCurrent(token, account) && session === opened) {
                if (opened.isOffline && mutableState.value.isEmptyOfflineRoot()) {
                    // The first pin starts with an empty unlock anchor and no issued child entries.
                    publishTransferListing(opened, "", token, account)
                } else {
                    refreshOfflineIndicators()
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            reportOfflineFailure(opened, account, token, failure)
        }
    }

    private fun refreshOfflineIndicators() {
        val current = mutableState.value
        if (current.mode != VaultRouteMode.CONTENTS || current.loading || current.preview != null) return
        // Reuse issued entries: a fresh list would invalidate an in-flight preview or mutation.
        mutableState.value =
            current.copy(
                entries =
                    current.entries.map { entry ->
                        presentedEntries[entry.id]?.remote?.let(::presentEntry)
                            ?: entry
                    },
            )
    }

    private fun VaultRouteState.isEmptyOfflineRoot(): Boolean {
        if (mode != VaultRouteMode.CONTENTS || loading || preview != null) return false
        return currentPath.isEmpty() && entries.isEmpty()
    }

    private fun reportOfflineFailure(
        opened: VaultRouteSession,
        account: String,
        token: Long,
        failure: Throwable,
    ) {
        if (isCurrent(token, account) && session === opened && !mutableState.value.loading) {
            mutableState.value =
                mutableState.value.copy(error = classifyVaultFailure(failure, VaultRouteError.OPERATION))
        }
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    private fun loadDiscovery(
        location: VaultLocation,
        path: String,
        token: Long,
    ) {
        val account = accountId ?: return
        lifecycle.trackOperation(
            viewModelScope.launch {
                try {
                    val entries = repository.folders(account, location, path)
                    if (isCurrent(token, account)) {
                        presentedEntries.clear()
                        mutableState.value =
                            mutableState.value.copy(
                                mode = VaultRouteMode.DISCOVERY,
                                entries = presentEntries(entries),
                                loading = false,
                                error = null,
                            )
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        VaultRouteError.DISCOVERY,
                        VaultFailureContext(token, account, classifyVaultIdentity = false),
                    )
                }
            },
        )
    }

    fun openVaultFolder(id: String) {
        val request = folderRequest(id) ?: return
        val token = nextGeneration()
        clearPreview()
        presentedEntries.clear()
        mutableState.value =
            mutableState.value.copy(
                currentPath = request.path,
                loading = true,
                error = null,
                entries = emptyList(),
                preview = null,
            )
        loadContents(request.session, request.path, token, request.account)
    }

    fun openPreview(id: String) {
        val token = nextGeneration()
        clearPreview()
        mutableState.value = mutableState.value.copy(preview = null, loading = false, error = null)
        val request = previewRequest(id, token) ?: return
        mutableState.value = mutableState.value.copy(loading = true, error = null, preview = null)
        lifecycle.trackOperation(viewModelScope.launch { previewContent.load(request) })
    }

    /** Creates a short-lived plaintext handoff only after the user accepts the external-app warning. */
    @Suppress("ReturnCount") // Reject missing session/account/source before starting any plaintext export.
    fun prepareOpenWith(
        id: String?,
        onReady: (VaultExternalCopyLease) -> Unit,
    ) {
        if (!canStartExternalHandoff()) return
        val opened = session ?: return
        val account = accountId ?: return
        val remote =
            if (id == null) {
                previewContent.loadedRequest?.takeIf { it.session === opened && it.account == account }?.remoteEntry
            } else {
                findEntry(id)?.remote
            }
        if (remote == null || remote.isFolder) return
        val request = VaultExternalHandoffRequest(opened, account, remote, generation)
        previewActions.openWith(request, onReady)
    }

    private fun canStartExternalHandoff(): Boolean =
        routeActive &&
            !mutableState.value.loading &&
            !mutableState.value.previewSaving &&
            mutableState.value.mode == VaultRouteMode.CONTENTS

    fun dismissPreview() {
        nextGeneration()
        clearPreview()
        mutableState.value = mutableState.value.copy(preview = null, loading = false)
    }

    /** Takes ownership of the UTF-8 buffer, including rejected and cancelled requests. */
    @Suppress("ReturnCount", "TooGenericExceptionCaught")
    fun savePreviewText(
        preview: VaultRoutePreview,
        bytes: ByteArray,
    ) = previewActions.saveText(preview, bytes)

    fun savePreviewTextRange(
        preview: VaultRoutePreview,
        offset: Long,
        length: Long,
        bytes: ByteArray,
    ) = previewActions.saveText(preview, bytes, offset, length)

    fun createFolder(name: String) =
        runSessionMutation { opened ->
            opened.createFolder(mutableState.value.currentPath, name)
            Unit
        }

    private fun canPrepareTransfer(): Boolean =
        !mutableState.value.loading && pendingTransfer == null && mutableState.value.mode == VaultRouteMode.CONTENTS

    private fun transferEntry(
        source: VaultFolder,
        sourceId: String,
        action: VaultEntryAction,
        path: String,
        approvedName: String? = null,
    ) {
        runSessionMutation { opened ->
            val name = approvedName ?: source.name
            val alternative = transferConflictName(opened, path, source, name)
            if (alternative != null) {
                pendingTransferSource = source
                mutableState.value =
                    mutableState.value.copy(
                        transferConflict =
                            VaultTransferConflict(
                                sourceId,
                                source.name,
                                path,
                                action,
                                alternative,
                            ),
                    )
            } else {
                val current = revalidateActionSource(opened, source)
                if (action ==
                    VaultEntryAction.COPY
                ) {
                    opened.copy(current, path, name)
                } else {
                    opened.move(current, path, name)
                }
            }
        }
    }

    private suspend fun transferConflictName(
        opened: VaultRouteSession,
        path: String,
        source: VaultFolder,
        name: String,
    ): String? {
        closeDirectory()
        return opened.openDirectory(path, true).use { snapshot ->
            if (!directoryContainsName(snapshot, name)) null else firstFreeName(snapshot, source)
        }
    }

    private suspend fun firstFreeName(
        snapshot: VaultRouteDirectorySnapshot,
        source: VaultFolder,
    ): String {
        var number = 1L
        while (true) {
            currentCoroutineContext().ensureActive()
            val candidate = numberedEncryptedCandidate(source.name, source.isFolder, number++)
            if (!directoryContainsName(snapshot, candidate)) return candidate
        }
    }

    private suspend fun directoryContainsName(
        snapshot: VaultRouteDirectorySnapshot,
        name: String,
    ): Boolean {
        var offset = 0L
        do {
            currentCoroutineContext().ensureActive()
            val page = snapshot.page(offset, VAULT_DIRECTORY_PAGE_SIZE)
            currentCoroutineContext().ensureActive()
            if (page.any { it.name == name }) return true
            offset += page.size
        } while (page.isNotEmpty() && offset < snapshot.totalCount)
        return false
    }

    fun resolveTransferConflict(keepBoth: Boolean) {
        val conflict = mutableState.value.transferConflict ?: return
        if (mutableState.value.loading || mutableState.value.mode != VaultRouteMode.CONTENTS) return
        val source = pendingTransferSource
        pendingTransferSource = null
        mutableState.value = mutableState.value.copy(transferConflict = null)
        if (keepBoth && source != null) {
            transferEntry(source, conflict.sourceId, conflict.action, conflict.path, conflict.proposedName)
        }
    }

    // Explicit guards reject stale operations; provider failures become safe UI states.
    @Suppress("ReturnCount", "TooGenericExceptionCaught")
    fun prepareUpload(onReady: () -> Unit) {
        val opened = session ?: return
        val account = accountId ?: return
        if (!canPrepareTransfer() || opened.isOffline) return
        val token = nextGeneration()
        val identity = opened.identity
        val path = mutableState.value.currentPath
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        lifecycle.trackOperation(
            viewModelScope.launch {
                try {
                    val encryptedParent = opened.encodeDirectoryPath(path)
                    if (!isCurrent(token, account) ||
                        session !== opened ||
                        opened.identity != identity
                    ) {
                        return@launch
                    }
                    pendingTransfer = PendingVaultTransfer.Upload(identity, encryptedParent)
                    pickerLease.arm()
                    mutableState.value = mutableState.value.copy(loading = false)
                    onReady()
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (isCurrent(token, account)) {
                        mutableState.value =
                            mutableState.value.copy(loading = false, error = VaultRouteError.OPERATION)
                    }
                }
            },
        )
    }

    fun acceptUploadUri(uri: Uri?) = acceptTransferUri(uri, isUpload = true)

    // Explicit guards reject stale operations; provider failures become safe UI states.
    @Suppress("ReturnCount", "CyclomaticComplexMethod", "TooGenericExceptionCaught")
    fun prepareExport(
        id: String,
        onReady: () -> Unit,
    ) {
        val opened = session ?: return
        val account = accountId ?: return
        val presented = findEntry(id) ?: return
        val entry = presented.remote
        if (entry.isFolder || !canPrepareTransfer()) return
        if (!entry.strongETag.isStrongVaultETag()) {
            mutableState.value = mutableState.value.copy(error = VaultRouteError.OPERATION)
            return
        }
        val token = nextGeneration()
        val identity = opened.identity
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        lifecycle.trackOperation(
            viewModelScope.launch {
                try {
                    val encryptedParent = opened.encodeDirectoryPath(entry.path.substringBeforeLast('/', ""))
                    if (!isCurrent(token, account) ||
                        session !== opened ||
                        opened.identity != identity
                    ) {
                        return@launch
                    }
                    pendingTransfer =
                        PendingVaultTransfer.Export(
                            identity = identity,
                            encryptedParentPath = encryptedParent,
                            id = entry.id,
                            encryptedPath = entry.encryptedPath,
                            strongETag = entry.strongETag,
                            observedSize = entry.size,
                        )
                    pickerLease.arm()
                    mutableState.value = mutableState.value.copy(loading = false)
                    onReady()
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (isCurrent(token, account)) {
                        mutableState.value =
                            mutableState.value.copy(loading = false, error = VaultRouteError.OPERATION)
                    }
                }
            },
        )
    }

    fun acceptExportUri(uri: Uri?) = acceptTransferUri(uri, isUpload = false)

    /** Backgrounding closes the route's session; only the bounded picker handoff may retain it. */
    fun onRouteStopped() {
        val request = pendingTransfer
        val opened = session
        val remaining = pickerLease.remainingMillis()
        val ownsPicker = request != null && request.uri == null && request.identity == opened?.identity
        if (!ownsPicker || remaining == 0L || deviceLocked()) {
            closeRouteSession()
            return
        }
        pickerSuspended = true
        clearPreview()
        clearVerifiedKeyMaterial()
        presentedEntries.clear()
        mutableState.value =
            mutableState.value.copy(
                entries = emptyList(),
                preview = null,
                loading = true,
                rootActionsVisible = false,
                canEnrollBiometric = false,
                biometricOfferPending = false,
                phoneRememberOffer = false,
            )
        pickerTimeout?.cancel()
        pickerTimeout =
            viewModelScope.launch {
                delay(remaining)
                closeRouteSession()
            }
    }

    fun onRouteStarted() {
        val selected = target ?: return
        if (routeActive && mutableState.value.mode == VaultRouteMode.UNLOCK && !mutableState.value.loading) {
            lifecycle.tryPhoneSessionUnlock(selected, nextGeneration())
        }
    }

    private fun deviceLocked(): Boolean =
        getApplication<Application>().getSystemService(KeyguardManager::class.java)?.isDeviceLocked != false

    private fun finishPickerHandoff() {
        if (pickerSuspended && (pickerLease.remainingMillis() == 0L || deviceLocked())) closeRouteSession()
        pickerTimeout?.cancel()
        pickerTimeout = null
        pickerSuspended = false
        pickerLease.clear()
    }

    // Explicit guards reject stale operations; provider failures become safe UI states.
    // Each identity and handoff state must be checked independently.
    @Suppress("ReturnCount", "CyclomaticComplexMethod")
    private fun acceptTransferUri(
        uri: Uri?,
        isUpload: Boolean,
    ) {
        if (!routeActive) return
        val pending = pendingTransfer ?: return
        if ((pending is PendingVaultTransfer.Upload) != isUpload) return
        if (pending.identity.accountId != accountId || pending.identity != currentTargetIdentity) {
            pendingTransfer = null
            return
        }
        val wasSuspended = pickerSuspended
        finishPickerHandoff()
        pendingTransfer = if (uri == null) null else pending.withUri(uri)
        if (uri == null && wasSuspended) {
            val opened = session
            val account = accountId
            if (opened != null && account != null) {
                loadContents(opened, mutableState.value.currentPath, nextGeneration(), account)
            }
        }
        if (uri != null) {
            val opened = session
            val account = accountId
            if (opened != null && account != null && mutableState.value.mode == VaultRouteMode.CONTENTS) {
                val token = nextGeneration()
                lifecycle.trackOperation(viewModelScope.launch { processPendingTransfer(opened, token, account) })
            } else {
                mutableState.value = mutableState.value.copy(error = VaultRouteError.TRANSFER_UNLOCK_REQUIRED)
            }
        }
    }

    // Explicit guards reject stale operations; provider failures become safe UI states.
    @Suppress("ReturnCount", "TooGenericExceptionCaught", "SwallowedException")
    private suspend fun processPendingTransfer(
        opened: VaultRouteSession,
        token: Long,
        account: String,
    ) {
        val request = pendingTransfer ?: return
        if (request.uri == null) return
        if (request.identity != opened.identity) {
            pendingTransfer = null
            mutableState.value = mutableState.value.copy(error = VaultRouteError.VAULT_CHANGED)
            return
        }
        // Consume before I/O so an ambiguous write is never repeated automatically.
        pendingTransfer = null
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        try {
            when (request) {
                is PendingVaultTransfer.Upload -> pickedTransferExecution.uploadPicked(opened, request, token, account)
                is PendingVaultTransfer.Export ->
                    pickedTransferExecution.exportWithCleanup(
                        opened,
                        request,
                        token,
                        account,
                    )
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            val fallback =
                if (request is PendingVaultTransfer.Export) {
                    VaultRouteError.EXPORT_FAILED
                } else {
                    VaultRouteError.OPERATION
                }
            reportFailure(failure, fallback, VaultFailureContext(token, account, lockOnRevocation = true))
        }
    }

    private fun isCurrentTransferSession(
        opened: VaultRouteSession,
        identity: VaultIdentity,
        token: Long,
        account: String,
    ): Boolean = isCurrent(token, account) && session === opened && identity == opened.identity

    private suspend fun verifyUploadDirectory(
        opened: VaultRouteSession,
        path: String,
    ) {
        closeDirectory()
        opened.openDirectory(path, true).use { currentCoroutineContext().ensureActive() }
    }

    private suspend fun revalidateExportSource(
        opened: VaultRouteSession,
        path: String,
        request: PendingVaultTransfer.Export,
    ): VaultFolder =
        findFreshDirectoryEntry(opened, path) {
            it.id == request.id &&
                it.encryptedPath == request.encryptedPath &&
                request.strongETag.isStrongVaultETag() &&
                it.strongETag == request.strongETag &&
                it.strongETag.isStrongVaultETag() &&
                it.size == request.observedSize &&
                !it.isFolder
        }

    private suspend fun publishTransferListing(
        opened: VaultRouteSession,
        path: String,
        token: Long,
        account: String,
    ) {
        if (!isCurrent(token, account) || session !== opened) return
        directoryContent.replace(opened, path, token, account)
    }

    private data class BoundaryPreparation(
        val opened: VaultRouteSession,
        val account: String,
        val source: VaultFolder,
        val location: VaultLocation,
    )

    @Suppress("ReturnCount") // Independent source/account/session guards precede any lease reissue.
    private fun boundaryPreparation(id: String): BoundaryPreparation? {
        val state = state.value
        val busy = state.loading || state.destinationPickerLoading
        if (busy || state.mode != VaultRouteMode.CONTENTS) return null
        val opened = session?.takeUnless { it.isOffline } ?: return null
        val account = accountId ?: return null
        val selected = findEntry(id) ?: destinationPicker.source(id) ?: return null
        if (selected.remote.isVaultRoot) return null
        val owner = target ?: return null
        val location =
            owner.location.copy(vaultPath = owner.vaultPath, remoteVaultId = owner.remoteVaultId, isVaultRoot = true)
        return BoundaryPreparation(opened, account, selected.remote, location)
    }

    @Suppress("TooGenericExceptionCaught") // Reissue failure remains scoped to the active route.
    internal fun prepareBoundaryTransfer(id: String, move: Boolean, onReady: (BoundaryTransferRequest) -> Unit) {
        val request = boundaryPreparation(id) ?: return
        val token = nextGeneration()
        clearDestinationPicker()
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        lifecycle.trackOperation(
            viewModelScope.launch {
                try {
                    val current = revalidateActionSource(request.opened, request.source)
                    if (!isCurrent(token, request.account) || session !== request.opened) return@launch
                    mutableState.value = mutableState.value.copy(loading = false)
                    onReady(
                        BoundaryTransferRequest(
                            accountId = request.account,
                            move = move,
                            unlocked = request.opened.boundaryEndpoint(request.location) to current.asBoundaryEntry(),
                            onComplete = ::dismissDestinationPicker,
                        ),
                    )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        VaultRouteError.OPERATION,
                        VaultFailureContext(token, request.account, lockOnRevocation = true),
                    )
                }
            },
        )
    }

    fun beginDestinationPicker(
        id: String,
        path: String,
    ) {
        val selected = findEntry(id) ?: return
        if (mutableState.value.loading || mutableState.value.mode != VaultRouteMode.CONTENTS) return
        destinationPicker.begin(selected, path, presentedEntries)
    }

    fun loadDestinationFolders(path: String) = destinationPicker.load(path, presentedEntries)

    private fun destinationOwnerSnapshot(): VaultDestinationOwnerSnapshot? {
        val opened = session
        val account = accountId
        val available = mutableState.value.mode == VaultRouteMode.CONTENTS && !mutableState.value.loading
        if (opened == null || account == null || !available) return null
        return VaultDestinationOwnerSnapshot(opened, account, mutableState.value.lockRevision, generation, showHidden)
    }

    fun destinationPage(previous: Boolean) = destinationPicker.page(previous)

    private fun reportDestinationFailure(
        owner: VaultDestinationOwnerSnapshot,
        failure: Exception,
    ) {
        reportFailure(
            failure,
            VaultRouteError.CONTENTS,
            VaultFailureContext(owner.routeGeneration, owner.account, lockOnRevocation = true),
        )
        if (session === owner.opened) {
            mutableState.value =
                mutableState.value.copy(
                    destinationPickerLoading = false,
                    destinationPickerError = mutableState.value.error ?: VaultRouteError.CONTENTS,
                )
        }
    }

    fun dismissDestinationPicker() {
        clearDestinationPicker()
        val opened = session ?: return
        val account = accountId ?: return
        if (!mutableState.value.loading && mutableState.value.mode == VaultRouteMode.CONTENTS) {
            mutableState.value = mutableState.value.copy(loading = true)
            loadContents(opened, mutableState.value.currentPath, nextGeneration(), account)
        }
    }

    private fun clearDestinationPicker() = destinationPicker.clear()

    private suspend fun revalidateActionSource(
        opened: VaultRouteSession,
        expected: VaultFolder,
    ): VaultFolder =
        findFreshDirectoryEntry(opened, expected.path.substringBeforeLast('/', "")) { candidate ->
            candidate.id == expected.id &&
                candidate.encryptedPath == expected.encryptedPath &&
                candidate.strongETag == expected.strongETag &&
                candidate.size == expected.size &&
                candidate.isFolder == expected.isFolder
        }

    /** Revalidation may visit many pages, but only the found page receives current action leases. */
    @Suppress("ThrowsCount") // Missing admission, stale coroutine ownership and absent source are distinct failures.
    private suspend fun findFreshDirectoryEntry(
        opened: VaultRouteSession,
        path: String,
        matches: (VaultFolder) -> Boolean,
    ): VaultFolder {
        val account = accountId ?: throw VaultSourceChangedException()
        val token = generation
        closeDirectory()
        val snapshot = opened.openDirectory(path, showHidden)
        var adopted = false
        try {
            val bookmarks = mutableListOf<Long>()
            var offset = 0L
            do {
                currentCoroutineContext().ensureActive()
                val entries = snapshot.page(offset, VAULT_DIRECTORY_PAGE_SIZE)
                currentCoroutineContext().ensureActive()
                if (!isCurrent(token, account) || session !== opened) throw CancellationException()
                val found = entries.singleOrNull(matches)
                if (found != null) {
                    directoryContent.adopt(snapshot, bookmarks)
                    adopted = true
                    mutableState.value =
                        mutableState.value.copy(
                            currentPath = path,
                            entries = presentEntries(entries),
                            directoryPage =
                                VaultDirectoryPageState(
                                    offset,
                                    snapshot.totalCount,
                                    entries.size,
                                    bookmarks.isNotEmpty(),
                                ),
                        )
                    return found
                }
                if (entries.isEmpty()) break
                bookmarks += offset
                offset += entries.size
            } while (offset < snapshot.totalCount)
            throw VaultSourceChangedException()
        } finally {
            if (!adopted) snapshot.close()
        }
    }

    private fun actionEntry(
        id: String,
        action: VaultEntryAction,
    ): PresentedVaultFolder? {
        val transfer = action == VaultEntryAction.MOVE || action == VaultEntryAction.COPY
        if (transfer && mutableState.value.destinationPickerLoading) return null
        return findEntry(id) ?: destinationPicker.source(id)?.takeIf { transfer }
    }

    fun onEntryAction(
        id: String,
        action: VaultEntryAction,
        value: String?,
    ) {
        val presented = actionEntry(id, action) ?: return
        when (action) {
            VaultEntryAction.KEEP_OFFLINE ->
                runSessionMutation(fallback = VaultRouteError.OFFLINE_PREPARATION) { opened ->
                    opened.pinOffline(presented.remote)
                }
            VaultEntryAction.DETAILS, VaultEntryAction.OPEN_WITH -> Unit
            VaultEntryAction.SAVE_COPY ->
                mutableState.value =
                    mutableState.value.copy(error = VaultRouteError.OPERATION)
            VaultEntryAction.DELETE -> runSessionMutation { opened -> opened.delete(presented.remote) }
            VaultEntryAction.RENAME ->
                value?.takeIf(String::isNotBlank)?.let { name ->
                    runSessionMutation { opened ->
                        opened.rename(presented.remote, name)
                        Unit
                    }
                }
            VaultEntryAction.MOVE, VaultEntryAction.COPY ->
                value?.let { path -> transferEntry(presented.remote, id, action, path) }
        }
    }

    // Explicit guards reject stale operations; provider failures become safe UI states.
    @Suppress("ReturnCount", "TooGenericExceptionCaught")
    private fun runSessionMutation(
        fallback: VaultRouteError = VaultRouteError.OPERATION,
        block: suspend (VaultRouteSession) -> Unit,
    ) {
        if (mutableState.value.loading || mutableState.value.mode != VaultRouteMode.CONTENTS) return
        val opened = session ?: return
        if (opened.isOffline) return
        val account = accountId ?: return
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        lifecycle.trackOperation(
            viewModelScope.launch {
                try {
                    block(opened)
                    if (!isCurrent(token, account) || session !== opened) return@launch
                    directoryContent.replace(opened, mutableState.value.currentPath, token, account)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        fallback,
                        VaultFailureContext(token, account, lockOnRevocation = true),
                    )
                }
            },
        )
    }

    internal fun editTarget(revision: Long): VaultLocation? {
        val location = managementTarget(revision)
        if (location?.kind == VaultLocationKind.SPACE_VAULT) return location
        if (location != null) showRootActions()
        return null
    }

    /** A scanner run can upload only into the unlocked session and directory that launched it. */
    @Suppress("ReturnCount") // Reject busy, offline or missing session targets before issuing a scanner lease.
    internal fun prepareScanner(): VaultScanLease? {
        if (mutableState.value.loading || mutableState.value.mode != VaultRouteMode.CONTENTS) return null
        val opened = session?.takeUnless { it.isOffline } ?: return null
        val account = accountId ?: return null
        val path = mutableState.value.currentPath
        val token = nextGeneration()
        clearPreview()
        mutableState.value = mutableState.value.copy(preview = null)
        val valid = { isCurrent(token, account) && session === opened }
        val destinationLabel =
            listOf(mutableState.value.selectedTitle.orEmpty(), path)
                .filter {
                    it.isNotBlank()
                }.joinToString(" / ")
        return VaultScanLease(destinationLabel, valid) { name, source, size, mime ->
            withContext(ioDispatcher) {
                check(valid())
                opened.queueUpload(path, name, source, size, mime)
            }
            // Acceptance owns a durable job even if the scanner lease expired while committing it.
            // Suppress stale UI feedback without turning that accepted job into a retryable scan.
            if (valid()) {
                mutableState.value =
                    mutableState.value.copy(queuedUploadCount = mutableState.value.queuedUploadCount + 1)
            }
        }
    }

    fun keepDirectoryOffline() {
        val path = mutableState.value.currentPath
        runSessionMutation(fallback = VaultRouteError.OFFLINE_PREPARATION) { it.pinOfflineDirectory(path) }
    }

    @Suppress("TooGenericExceptionCaught") // Cleanup I/O errors become a retryable UI state; cancellation is rethrown.
    fun removeOfflineCopy() {
        val identity = session?.identity ?: return
        lock()
        val token = generation
        val account = accountId ?: return
        viewModelScope.launch {
            try {
                withContext(ioDispatcher) { repository.removeOffline(identity) }
                if (isCurrent(token, account)) showOfflineCatalog()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                reportFailure(failure, VaultRouteError.OPERATION, VaultFailureContext(token, account))
            }
        }
    }

    fun managementTarget(expectedLockRevision: Long): VaultLocation? =
        rootManagement.managementTarget(expectedLockRevision)

    fun isManagementUnlocked(
        location: VaultLocation,
        expectedLockRevision: Long,
    ): Boolean = rootManagement.isManagementUnlocked(location, expectedLockRevision)

    fun managedSpaceChanged(
        location: VaultLocation,
        expectedLockRevision: Long,
    ) = rootManagement.managedSpaceChanged(location, expectedLockRevision)

    fun managedSpaceLifecycleChanged(
        expectedLockRevision: Long,
        onComplete: () -> Unit,
    ) = rootManagement.managedSpaceLifecycleChanged(expectedLockRevision, onComplete)

    fun showRootActions() = rootManagement.showRootActions()

    fun dismissRootActions() = rootManagement.dismissRootActions()

    private fun maybeOpenRootActions() {
        val current = mutableState.value
        val ready =
            current.mode == VaultRouteMode.CONTENTS &&
                current.currentPath.isEmpty() &&
                !current.biometricOfferPending
        if (openRootMenuAfterUnlock && ready) {
            openRootMenuAfterUnlock = false
            mutableState.value = current.copy(rootActionsVisible = true)
        }
    }

    fun renameRoot(
        name: String,
        expectedLockRevision: Long,
    ) = rootManagement.renameRoot(name, expectedLockRevision)

    fun deleteRoot(expectedLockRevision: Long) = rootManagement.deleteRoot(expectedLockRevision)

    private fun folderRequest(id: String): VaultContentsRequest? {
        val entry = findEntry(id)?.route?.takeIf { it.isFolder } ?: return null
        return contentsRequest(entry.path)
    }

    /** Decoded thumbnails stay in memory and retain their originating route and source lease. */
    suspend fun loadThumbnail(id: String): ByteArray? = thumbnailRequest(id)?.let { previewContent.loadThumbnail(it) }

    @Suppress("ReturnCount") // Reject unsupported images before decrypting or allocating thumbnail data.
    private fun thumbnailRequest(id: String): VaultThumbnailRequest? {
        if (mutableState.value.mode != VaultRouteMode.CONTENTS || mutableState.value.loading) return null
        val entry = findEntry(id) ?: return null
        if (entry.route.isFolder ||
            (vaultPreviewKind(entry.route.name) != VaultPreviewKind.IMAGE && !isVaultVideo(entry.route.name))
        ) {
            return null
        }
        val opened = session ?: return null
        val account = accountId ?: return null
        return VaultThumbnailRequest(opened, account, generation, entry)
    }

    private fun isThumbnailCurrent(request: VaultThumbnailRequest): Boolean =
        isCurrent(request.token, request.account) &&
            session === request.session &&
            findEntry(request.entry.route.id) === request.entry &&
            !mutableState.value.loading

    @Suppress("ReturnCount") // Reject invalid or stale preview requests before starting any work.
    private fun previewRequest(id: String, token: Long): VaultPreviewRequest? {
        val presented = findEntry(id) ?: return null
        val entry = presented.route
        if (entry.isFolder) return null
        val kind = vaultPreviewKind(entry.name)
        if (kind == VaultPreviewKind.UNSUPPORTED) return failPreviewRequest()
        val maximumBytes = Long.MAX_VALUE
        val opened = session ?: return null
        val account = accountId ?: return null
        return VaultPreviewRequest(
            session = opened,
            account = account,
            remoteEntry = presented.remote,
            title = entry.name,
            kind = kind,
            maximumBytes = maximumBytes,
            token = token,
        )
    }

    private fun failPreviewRequest(): VaultPreviewRequest? {
        mutableState.value = mutableState.value.copy(error = VaultRouteError.PREVIEW)
        return null
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    private fun loadContents(
        opened: VaultRouteSession,
        path: String,
        token: Long,
        account: String,
    ) {
        closeDirectory()
        mutableState.value = mutableState.value.copy(entries = emptyList(), directoryPage = null)
        lifecycle.trackOperation(
            viewModelScope.launch {
                try {
                    directoryContent.replace(opened, path, token, account)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        VaultRouteError.CONTENTS,
                        VaultFailureContext(token, account, lockOnRevocation = true),
                    )
                }
            },
        )
    }

    fun setShowHidden(value: Boolean) {
        if (showHidden == value) return
        showHidden = value
        val destination = mutableState.value.destinationPickerPath
        if (destination != null) {
            loadDestinationFolders(destination)
        } else if (session != null && mutableState.value.mode == VaultRouteMode.CONTENTS) {
            retry()
        }
    }

    @Suppress("ReturnCount") // Session, account and directory admission remain independent of page loading.
    fun directoryPage(previous: Boolean) {
        val opened = session ?: return
        val account = accountId ?: return
        val request = directoryContent.pageRequest(opened, account, previous) ?: return
        val token = nextGeneration()
        clearPreview()
        presentedEntries.clear()
        mutableState.value =
            mutableState.value.copy(entries = emptyList(), loading = true, preview = null, error = null)
        lifecycle.trackOperation(viewModelScope.launch { directoryContent.loadPage(request, token) })
    }

    private fun closeDirectory() = directoryContent.close()

    fun up() {
        when (mutableState.value.mode) {
            VaultRouteMode.DISCOVERY -> upDiscovery()
            VaultRouteMode.CONTENTS -> upContents()
            else -> Unit
        }
    }

    private fun upDiscovery() {
        val source = currentSource ?: return
        val path = mutableState.value.currentPath.substringBeforeLast('/', "")
        val token = nextGeneration()
        mutableState.value =
            mutableState.value.copy(
                currentPath = path,
                browseTitle = path.substringAfterLast('/').ifEmpty { source.title },
                loading = true,
            )
        loadDiscovery(source, path, token)
    }

    private fun upContents() {
        val path = mutableState.value.currentPath.substringBeforeLast('/', "")
        val request = contentsRequest(path) ?: return
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(currentPath = path, loading = true, error = null)
        loadContents(request.session, request.path, token, request.account)
    }

    private fun contentsRequest(path: String): VaultContentsRequest? {
        val opened = session
        val account = accountId
        return if (opened != null && account != null) VaultContentsRequest(opened, path, account) else null
    }

    fun retry() {
        if (lifecycle.retryDeletedVaultCleanup()) return
        when (mutableState.value.mode) {
            VaultRouteMode.CATALOG -> {
                val direct = directLocation
                val account = accountId
                if (direct != null && account != null) {
                    selectDirectLocation(account, direct)
                } else if (mutableState.value.offlineCatalog) {
                    showOfflineCatalog()
                } else {
                    refreshCatalog()
                }
            }
            VaultRouteMode.DISCOVERY ->
                currentSource?.let { source ->
                    val token = nextGeneration()
                    mutableState.value = mutableState.value.copy(loading = true, error = null)
                    loadDiscovery(source, mutableState.value.currentPath, token)
                }
            VaultRouteMode.UNLOCK -> mutableState.value = mutableState.value.copy(error = null)
            VaultRouteMode.CONTENTS -> {
                val request = contentsRequest(mutableState.value.currentPath) ?: return
                val token = nextGeneration()
                mutableState.value = mutableState.value.copy(loading = true, error = null)
                loadContents(request.session, request.path, token, request.account)
            }
        }
    }

    private fun reportFailure(
        failure: Throwable,
        fallback: VaultRouteError,
        context: VaultFailureContext,
    ) {
        if (!isCurrent(context.token, context.account)) return
        val error = classifyVaultFailure(failure, fallback, context.classifyVaultIdentity)
        // Wrong offline passwords and stale selected files do not revoke an existing snapshot.
        val onlineTarget = target?.location?.offlineOnly != true && session?.isOffline != true
        val revokedAccess =
            failure !is VaultSourceChangedException &&
                error in setOf(VaultRouteError.ACCESS_DENIED, VaultRouteError.VAULT_CHANGED)
        if (onlineTarget && revokedAccess) {
            val identity = session?.identity ?: target?.expectedIdentity()
            if (identity != null) {
                viewModelScope.launch(ioDispatcher) {
                    try {
                        repository.removeOffline(identity)
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        // Store revocation is durable before deletion; retain the original access error.
                    }
                }
            }
        }
        if (context.lockOnRevocation && error.requiresVaultRelock()) {
            lock()
            mutableState.value = mutableState.value.copy(error = error)
        } else {
            mutableState.value = mutableState.value.copy(loading = false, error = error)
        }
    }

    private fun findEntry(id: String): PresentedVaultFolder? = presentedEntries[id]

    private fun presentEntries(entries: List<VaultFolder>): List<VaultRouteEntry> {
        presentedEntries.clear()
        return entries.map(::presentEntry)
    }

    private fun presentEntry(entry: VaultFolder): VaultRouteEntry {
        val key = entry.id + "\u0000" + entry.path
        val presented =
            PresentedVaultFolder(
                VaultRouteEntry(
                    id = key,
                    name = entry.name,
                    path = entry.path,
                    isFolder = entry.isFolder,
                    isVaultRoot = entry.isVaultRoot,
                    size = entry.size,
                    contentType = entry.contentType,
                    offlineAvailable = session?.offlineAvailable(entry),
                    displaySize = if (entry.isFolder) null else encryptedPlaintextSize(entry.size),
                ),
                entry,
            )
        presentedEntries[key] = presented
        return presented.route
    }

    private fun presentLocation(location: VaultLocation): VaultRouteLocation =
        VaultRouteLocation(
            id = locationKey(location),
            title = location.title,
            kind =
                when (location.kind) {
                    VaultLocationKind.FOLDER_VAULT -> VaultLocationKindUi.FOLDER_VAULT
                    VaultLocationKind.SPACE_VAULT -> VaultLocationKindUi.SPACE_VAULT
                    VaultLocationKind.PERSONAL -> VaultLocationKindUi.PERSONAL
                    VaultLocationKind.SPACE -> VaultLocationKindUi.SPACE
                },
            isVaultRoot = location.isVaultRoot,
            offline = location.offlineOnly,
        )

    private fun locationKey(location: VaultLocation): String {
        val value =
            listOf(
                location.accountId,
                location.canonicalServer,
                location.driveId,
                location.remoteVaultId,
                location.vaultPath,
                location.kind.name,
                location.offlineOnly.toString(),
            ).joinToString("\u0000")
        return MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8)).toHex()
    }

    private fun clearPreview() = previewContent.clear()

    fun unlock(password: CharArray) = lifecycle.unlock(password)

    fun lock() = lifecycle.lock()

    fun onDeviceLocked() = lifecycle.onDeviceLocked()

    fun prepareBiometricUnlock(): Cipher? = lifecycle.prepareBiometricUnlock()

    fun completeBiometricUnlock(cipher: Cipher?) = lifecycle.completeBiometricUnlock(cipher)

    fun cancelBiometricUnlock() = lifecycle.cancelBiometricUnlock()

    fun prepareBiometricEnrollment(): Cipher? = lifecycle.prepareBiometricEnrollment()

    fun acceptBiometricOffer() = lifecycle.acceptBiometricOffer()

    fun declineBiometricOffer() = lifecycle.declineBiometricOffer()

    fun rememberOnPhone() = lifecycle.rememberOnPhone()

    fun completeBiometricEnrollment(cipher: Cipher?) = lifecycle.completeBiometricEnrollment(cipher)

    fun cancelBiometricEnrollment() = lifecycle.cancelBiometricEnrollment()

    fun forgetBiometric(expectedLockRevision: Long) = lifecycle.forgetBiometric(expectedLockRevision)

    private fun showPasswordUnlock(selected: VaultSessionTarget) = lifecycle.showPasswordUnlock(selected)

    private fun closeRouteSession() = lifecycle.closeRouteSession()

    private fun closeSession() = lifecycle.closeSession()

    private fun clearVerifiedKeyMaterial() = lifecycle.clearVerifiedKeyMaterial()

    private fun clearSensitiveState() = lifecycle.clearSensitiveState()

    private fun nextGeneration(): Long = lifecycle.nextGeneration()

    private fun invalidateRequests() = lifecycle.invalidateRequests()

    private fun isCurrent(
        token: Long,
        account: String,
    ): Boolean = lifecycle.isCurrent(token, account)

    override fun onCleared() {
        leaveRoute()
        super.onCleared()
    }
}

const val VAULT_DIRECTORY_PAGE_SIZE = 128

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte -> "%02x".format(byte) }

internal fun classifyVaultFailure(
    failure: Throwable,
    fallback: VaultRouteError,
    classifyVaultIdentity: Boolean = true,
): VaultRouteError =
    when (failure) {
        is VaultIdentityChangedException, is VaultSourceChangedException -> VaultRouteError.VAULT_CHANGED
        is VaultUnlockException ->
            when (failure.failure) {
                VaultUnlockFailure.PASSWORD_NOT_PROVEN -> VaultRouteError.UNLOCK_PROOF
            }
        else -> classifyVaultNetworkFailure(failure.toOpenCloudError(), fallback, classifyVaultIdentity)
    }

private fun classifyVaultNetworkFailure(
    error: OpenCloudError,
    fallback: VaultRouteError,
    classifyVaultIdentity: Boolean,
): VaultRouteError =
    VAULT_NETWORK_ERRORS[error] ?: when (error) {
        is OpenCloudError.NotReady, is OpenCloudError.RateLimited -> VaultRouteError.SERVER_BUSY
        OpenCloudError.PreconditionFailed, OpenCloudError.NotFound ->
            if (classifyVaultIdentity) VaultRouteError.VAULT_CHANGED else fallback
        else -> fallback
    }

private val VAULT_NETWORK_ERRORS =
    mapOf(
        OpenCloudError.Connectivity to VaultRouteError.CONNECTION,
        OpenCloudError.Timeout to VaultRouteError.CONNECTION,
        OpenCloudError.Trust to VaultRouteError.SECURE_CONNECTION,
        OpenCloudError.InvalidResponse to VaultRouteError.SERVER_RESPONSE,
        OpenCloudError.DirectoryListingTooLarge to VaultRouteError.LISTING_TOO_LARGE,
        OpenCloudError.EncryptedOfflineIndexFull to VaultRouteError.OFFLINE_INDEX_FULL,
        OpenCloudError.LocalStorage to VaultRouteError.LOCAL_STORAGE,
        OpenCloudError.LocalStorageWriteFailed to VaultRouteError.LOCAL_SAVE,
        OpenCloudError.SourceUnavailable to VaultRouteError.SOURCE_UNAVAILABLE,
        OpenCloudError.SourceChanged to VaultRouteError.SOURCE_CHANGED,
        OpenCloudError.SourcePermissionDenied to VaultRouteError.SOURCE_PERMISSION,
        OpenCloudError.DownloadIntegrity to VaultRouteError.INTEGRITY,
        OpenCloudError.EncryptedUnlockFailed to VaultRouteError.SAVED_UNLOCK,
        OpenCloudError.OfflineSnapshotChanged to VaultRouteError.OFFLINE_CHANGED,
        OpenCloudError.OfflineGroupBusy to VaultRouteError.OFFLINE_BUSY,
        OpenCloudError.QuotaExceeded to VaultRouteError.REMOTE_QUOTA,
        OpenCloudError.Conflict to VaultRouteError.NAME_CONFLICT,
        OpenCloudError.AuthenticationRequired to VaultRouteError.AUTHENTICATION,
        OpenCloudError.ClientRegistrationRequired to VaultRouteError.AUTHENTICATION,
        OpenCloudError.AccessDenied to VaultRouteError.ACCESS_DENIED,
    )

private class VaultSourceChangedException : IllegalStateException("The selected source changed.")

internal class VaultIdentityChangedException : IllegalStateException("Vault identity changed during unlock.")

internal fun VaultRouteError.requiresVaultRelock(): Boolean =
    this == VaultRouteError.AUTHENTICATION ||
        this == VaultRouteError.ACCESS_DENIED ||
        this == VaultRouteError.VAULT_CHANGED

private data class VaultContentsRequest(
    val session: VaultRouteSession,
    val path: String,
    val account: String,
)

internal data class VaultFailureContext(
    val token: Long,
    val account: String,
    val lockOnRevocation: Boolean = false,
    val classifyVaultIdentity: Boolean = true,
)

private fun String?.isStrongVaultETag(): Boolean = this != null && length >= 2 && startsWith('"') && endsWith('"')

/** Process-local callback lease: no scanner destination or key is serialized. */
internal class VaultScanLease(
    val destinationLabel: String,
    val isValid: () -> Boolean,
    val upload: suspend (String, InputStream, Long, String) -> Unit,
)

internal fun numberedEncryptedCandidate(
    name: String,
    folder: Boolean,
    number: Long,
): String {
    val dot = if (folder) -1 else name.lastIndexOf('.').takeIf { it > 0 } ?: -1
    val stem = if (dot < 0) name else name.substring(0, dot)
    val extension = if (dot < 0) "" else name.substring(dot)
    return "$stem ($number)$extension"
}

/** Rclone framing: 32-byte header, 16-byte tag per 64-KiB plaintext block. */
internal fun encryptedPlaintextSize(ciphertextSize: Long): Long? {
    if (ciphertextSize < 32) return null
    val payload = ciphertextSize - 32
    val remainder = payload % 65552
    return if (remainder in 1..16) null else (payload / 65552) * 65536 + if (remainder == 0L) 0 else remainder - 16
}

internal val MAX_VAULT_EDIT_TEXT_BYTES: Int
    get() = (Runtime.getRuntime().maxMemory() / 16).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()

internal fun validEditableText(bytes: ByteArray): Boolean {
    if (bytes.size > MAX_VAULT_EDIT_TEXT_BYTES) return false
    return try {
        val decoded =
            StandardCharsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
        decoded.clear()
        while (decoded.hasRemaining()) decoded.put('\u0000')
        true
    } catch (_: java.nio.charset.CharacterCodingException) {
        false
    }
}
