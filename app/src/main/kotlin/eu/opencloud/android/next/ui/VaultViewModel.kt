package eu.opencloud.android.next.ui

import android.app.Application
import android.app.KeyguardManager
import android.content.ContentResolver
import android.graphics.Bitmap
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultKeyStore
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultPreferences
import eu.opencloud.android.next.core.sync.VaultExternalCopyLease
import eu.opencloud.android.next.core.sync.VaultExternalCopyStore
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.core.sync.VaultOfflineSession
import eu.opencloud.android.next.core.sync.VaultOfflineStore
import eu.opencloud.android.next.core.sync.VaultRepository
import eu.opencloud.android.next.core.sync.VaultSession
import eu.opencloud.android.next.core.sync.VaultUnlockException
import eu.opencloud.android.next.core.sync.VaultUnlockFailure
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import javax.crypto.Cipher

@Suppress("LargeClass") // One owner serializes account, session, preview, and lock generations for this route.
class VaultViewModel internal constructor(
    application: Application,
    private val repository: VaultRouteRepository,
    private val biometricStore: VaultBiometricKeyStore,
    private val biometricPreferences: VaultOfferPreferences = AndroidVaultOfferPreferences(application),
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
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

    private var accountId: String? = null
    private var routeActive = false
    private var openRootMenuAfterUnlock = false
    private var generation = 0L
    private var catalogJob: Job? = null
    private var operationJob: Job? = null
    private var session: VaultRouteSession? = null
    private var loadedPreviewRequest: VaultPreviewRequest? = null
    private var pendingTransferSource: VaultFolder? = null
    private var currentSource: VaultLocation? = null
    private var target: VaultTarget? = null
    private var currentTargetIdentity: VaultIdentity? = null
    private var verifiedKeyMaterial: ByteArray? = null
    private var pendingBiometricIdentity: VaultIdentity? = null
    private var pendingEnrollmentIdentity: VaultIdentity? = null
    private var pendingDeletedVaultCleanup: VaultIdentity? = null
    private val thumbnailMutex = Mutex()
    private val presentedEntries = mutableMapOf<String, PresentedVaultFolder>()
    private var pendingTransfer: PendingVaultTransfer? = null
    private val pickerLease = VaultPickerLease()
    private var pickerTimeout: Job? = null
    private var pickerSuspended = false
    private var destinationJob: Job? = null
    private var destinationGeneration = 0L

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
        routeActive = true
        this.accountId = accountId
        directLocation = initialLocation
        openRootMenuAfterUnlock = openMenuAfterUnlock
        if (initialLocation == null) {
            if (offlineCatalog) showOfflineCatalog() else refreshCatalog()
        } else {
            selectDirectLocation(accountId, initialLocation)
        }
    }

    fun leaveRoute() {
        routeActive = false
        accountId = null
        invalidateRequests()
        clearSensitiveState()
        currentSource = null
        sourceLocations = emptyMap()
        directLocation = null
        pendingTransfer = null
        target = null
        currentTargetIdentity = null
        mutableState.value = VaultRouteState(lockRevision = mutableState.value.lockRevision + 1)
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    fun refreshCatalog() {
        loadCatalog(offlineOnly = false)
    }

    fun showOfflineCatalog() {
        closeSession()
        target = null
        currentSource = null
        currentTargetIdentity = null
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
        val selected = VaultTarget(location, location.vaultPath, location.title, location.remoteVaultId)
        target = selected
        currentSource = null
        showPasswordUnlock(selected)
    }

    fun selectLocation(id: String) {
        val location = sourceLocations[id] ?: return
        clearSensitiveState()
        currentSource = location
        if (location.isVaultRoot) {
            val selectedTarget = VaultTarget(location, location.vaultPath, location.title, location.remoteVaultId)
            target = selectedTarget
            showPasswordUnlock(selectedTarget)
        } else {
            target = null
            currentTargetIdentity = null
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
        val selectedTarget = VaultTarget(folderLocation, entry.path, entry.name, presented.remote.id)
        target = selectedTarget
        showPasswordUnlock(selectedTarget)
    }

    fun showCatalog() {
        nextGeneration()
        closeSession()
        currentSource = null
        target = null
        currentTargetIdentity = null
        clearVerifiedKeyMaterial()
        clearPreview()
        mutableState.value =
            mutableState.value.copy(
                mode = VaultRouteMode.CATALOG,
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
                lockRevision = mutableState.value.lockRevision + 1,
            )
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    fun unlock(password: CharArray) {
        val account = accountId
        val selected = target
        if (account == null || selected == null || password.isEmpty()) {
            password.fill('\u0000')
            mutableState.value = mutableState.value.copy(error = VaultRouteError.UNLOCK)
            return
        }
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(loading = true, error = null, mode = VaultRouteMode.UNLOCK)
        val unlockJob =
            viewModelScope.launch {
                var unlocked: VaultRouteSession? = null
                try {
                    unlocked = repository.unlock(account, selected.location, selected.vaultPath, password)
                    if (!isCurrent(token, account)) {
                        unlocked.close()
                        return@launch
                    }
                    installSession(unlocked, selected, token, account, captureKeyMaterial = true)
                    unlocked = null
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(failure, VaultRouteError.UNLOCK, VaultFailureContext(token, account))
                } finally {
                    password.fill('\u0000')
                    unlocked?.close()
                }
            }
        unlockJob.invokeOnCompletion { password.fill('\u0000') }
        operationJob = unlockJob
    }

    private suspend fun installSession(
        opened: VaultRouteSession,
        selected: VaultTarget,
        token: Long,
        account: String,
        captureKeyMaterial: Boolean,
    ) {
        var capturedMaterial: ByteArray? = null
        try {
            if (opened.identity != selected.expectedIdentity()) throw VaultIdentityChangedException()
            val entries = opened.list("")
            if (!isCurrent(token, account)) {
                opened.close()
                return
            }
            if (captureKeyMaterial) {
                capturedMaterial =
                    try {
                        opened.exportVerifiedKeyMaterial()
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        null
                    }
            }
            if (!isCurrent(token, account)) {
                opened.close()
                return
            }
            val enrollment = enrollmentStatus(opened.identity)
            val offerPending =
                captureKeyMaterial &&
                    capturedMaterial != null &&
                    !enrollment.first &&
                    preferenceStatus(opened.identity) == null
            val canEnroll = captureKeyMaterial && capturedMaterial != null && !enrollment.first
            closeSession()
            clearVerifiedKeyMaterial()
            session = opened
            currentTargetIdentity = opened.identity
            verifiedKeyMaterial = capturedMaterial
            capturedMaterial = null
            presentedEntries.clear()
            mutableState.value =
                mutableState.value.copy(
                    mode = VaultRouteMode.CONTENTS,
                    offline = opened.isOffline,
                    selectedLocation = presentLocation(selected.location),
                    selectedTitle = selected.title,
                    browseTitle = null,
                    currentPath = "",
                    entries = presentEntries(entries),
                    loading = false,
                    error = null,
                    biometricEnrolled = enrollment.first,
                    biometricNeedsForget = enrollment.second,
                    canEnrollBiometric = canEnroll,
                    biometricOfferPending = offerPending,
                    rootActionsVisible = mutableState.value.rootActionsVisible,
                    preview = null,
                )
            maybeOpenRootActions()
            processPendingTransfer(opened, token, account)
        } finally {
            capturedMaterial?.fill(0)
        }
    }

    private fun showPasswordUnlock(selected: VaultTarget) {
        nextGeneration()
        closeSession()
        clearVerifiedKeyMaterial()
        clearPreview()
        val expectedIdentity = selected.expectedIdentity()
        val enrollment = enrollmentStatus(expectedIdentity)
        currentTargetIdentity = expectedIdentity
        mutableState.value =
            mutableState.value.copy(
                mode = VaultRouteMode.UNLOCK,
                selectedLocation = presentLocation(selected.location),
                selectedTitle = selected.title,
                browseTitle = null,
                currentPath = "",
                entries = emptyList(),
                loading = false,
                error = null,
                biometricEnrolled = enrollment.first,
                biometricNeedsForget = enrollment.second,
                canEnrollBiometric = false,
                biometricOfferPending = false,
                preview = null,
                lockRevision = mutableState.value.lockRevision + 1,
            )
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    private fun loadDiscovery(
        location: VaultLocation,
        path: String,
        token: Long,
    ) {
        val account = accountId ?: return
        operationJob =
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
            }
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
        operationJob = viewModelScope.launch { loadPreview(request) }
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
                loadedPreviewRequest?.takeIf { it.session === opened && it.account == account }?.remoteEntry
            } else {
                findEntry(id)?.remote
            }
        if (remote == null || remote.isFolder) return
        val request = ExternalHandoffRequest(opened, account, remote, generation)
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        operationJob = viewModelScope.launch { createExternalHandoff(request, onReady) }
    }

    private fun canStartExternalHandoff(): Boolean =
        routeActive &&
            !mutableState.value.loading &&
            !mutableState.value.previewSaving &&
            mutableState.value.mode == VaultRouteMode.CONTENTS

    @Suppress("TooGenericExceptionCaught") // Download, storage and Android launcher failures become safe UI state.
    private suspend fun createExternalHandoff(
        request: ExternalHandoffRequest,
        onReady: (VaultExternalCopyLease) -> Unit,
    ) {
        var lease: VaultExternalCopyLease? = null
        try {
            val current = refreshExternalHandoffSource(request) ?: return
            withContext(ioDispatcher) {
                lease =
                    VaultExternalCopyStore.create(
                        getApplication(),
                        current.name,
                        eu.opencloud.android.next.core.model
                            .fileMimeType(current.name, current.contentType),
                    ) { sink -> request.session.download(current, sink, Long.MAX_VALUE) }
            }
            if (!isCurrent(request.token, request.account) || session !== request.session) return
            mutableState.value = mutableState.value.copy(loading = false)
            onReady(requireNotNull(lease))
            lease = null // The external-launch owner now cleans up on return or expiry.
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (isCurrent(request.token, request.account) && session === request.session) {
                mutableState.value = mutableState.value.copy(loading = false)
                reportFailure(
                    failure,
                    VaultRouteError.PREVIEW,
                    VaultFailureContext(request.token, request.account, true),
                )
            }
        } finally {
            lease?.cleanup()
        }
    }

    private suspend fun refreshExternalHandoffSource(request: ExternalHandoffRequest): VaultFolder? {
        val entries =
            withContext(ioDispatcher) {
                request.session.list(request.remote.path.substringBeforeLast('/', ""))
            }
        val current = matchActionSource(entries, request.remote)
        if (!isCurrent(request.token, request.account) || session !== request.session) return null
        // Listing replaces issued entry leases. Keep browser actions and the same-content editor bound to fresh leases.
        mutableState.value = mutableState.value.copy(entries = presentEntries(entries))
        loadedPreviewRequest?.takeIf { it.remoteEntry == request.remote }?.let {
            loadedPreviewRequest = it.copy(remoteEntry = current)
        }
        return current
    }

    private data class ExternalHandoffRequest(
        val session: VaultRouteSession,
        val account: String,
        val remote: VaultFolder,
        val token: Long,
    )

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
    ) = savePreviewTextContent(preview, bytes)

    fun savePreviewTextRange(
        preview: VaultRoutePreview,
        offset: Long,
        length: Long,
        bytes: ByteArray,
    ) = savePreviewTextContent(preview, bytes, offset, length)

    @Suppress("TooGenericExceptionCaught") // Server, stream and crypto failures share cancellation-safe cleanup.
    private fun savePreviewTextContent(
        preview: VaultRoutePreview,
        bytes: ByteArray,
        offset: Long? = null,
        length: Long = 0,
    ) {
        val request = loadedPreviewRequest
        val backing = preview.backing
        val rangeValid = validPreviewTextRange(backing, offset, length, bytes.size)
        if (request == null || !canSavePreview(preview, request) || !rangeValid) {
            bytes.fill(0)
            return
        }
        if (!validEditableText(bytes)) {
            bytes.fill(0)
            mutableState.value = mutableState.value.copy(previewSaveError = VaultRouteError.OPERATION)
            return
        }
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(previewSaving = true, previewSaveError = null)
        operationJob =
            viewModelScope.launch {
                try {
                    withContext(ioDispatcher) {
                        val input =
                            if (offset == null) {
                                ByteArrayInputStream(bytes)
                            } else {
                                EncryptedTextReplacementStream(
                                    requireNotNull(backing).inputStream(),
                                    offset,
                                    length,
                                    bytes,
                                )
                            }
                        input.use {
                            val total =
                                if (offset == null) {
                                    bytes.size.toLong()
                                } else {
                                    requireNotNull(backing).size - length + bytes.size
                                }
                            request.session.replaceText(request.remoteEntry, it, total)
                        }
                    }
                    if (!isCurrent(token, request.account) || session !== request.session) return@launch
                    clearPreview()
                    mutableState.value = mutableState.value.copy(preview = null, loading = true, error = null)
                    loadContents(request.session, mutableState.value.currentPath, token, request.account)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    if (isCurrent(token, request.account) && session === request.session) {
                        // A sent overwrite consumes the issued ETag, even if its outcome is ambiguous.
                        loadedPreviewRequest = null
                        mutableState.value =
                            mutableState.value.copy(
                                preview = preview.copy(editable = false),
                                previewSaving = false,
                                previewSaveError = classifyVaultFailure(failure, VaultRouteError.OPERATION),
                            )
                        reportFailure(
                            failure,
                            VaultRouteError.OPERATION,
                            VaultFailureContext(token, request.account, lockOnRevocation = true),
                        )
                    }
                } finally {
                    bytes.fill(0)
                }
            }
        // Also covers cancellation before the launched coroutine has entered its try/finally.
        operationJob?.invokeOnCompletion { bytes.fill(0) }
    }

    private fun validPreviewTextRange(
        backing: EncryptedPreviewBacking?,
        offset: Long?,
        length: Long,
        replacementSize: Int,
    ): Boolean =
        offset == null ||
            runCatching {
                val size = requireNotNull(backing).size
                offset >= 0 &&
                    length >= 0 &&
                    offset <= size &&
                    length <= size - offset &&
                    replacementSize.toLong() <= Long.MAX_VALUE - (size - length)
            }.getOrDefault(false)

    private fun canSavePreview(
        preview: VaultRoutePreview,
        request: VaultPreviewRequest,
    ): Boolean =
        routeActive &&
            mutableState.value.mode == VaultRouteMode.CONTENTS &&
            !mutableState.value.loading &&
            !mutableState.value.previewSaving &&
            mutableState.value.preview === preview &&
            preview.editable &&
            preview.kind == VaultPreviewKind.TEXT &&
            !request.session.isOffline &&
            session === request.session &&
            isCurrent(request.token, request.account)

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
            val names = opened.list(path).map { it.name }.toSet()
            val name = approvedName ?: source.name
            if (name in names) {
                pendingTransferSource = source
                mutableState.value =
                    mutableState.value.copy(
                        transferConflict =
                            VaultTransferConflict(
                                sourceId,
                                source.name,
                                path,
                                action,
                                numberedEncryptedName(source.name, source.isFolder, names),
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
        operationJob =
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
            }
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
        operationJob =
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
            }
    }

    fun acceptExportUri(uri: Uri?) = acceptTransferUri(uri, isUpload = false)

    /** Keep only a bounded picker-owned session; ordinary backgrounding still locks immediately. */
    fun onRouteStopped() {
        val request = pendingTransfer
        val opened = session
        val remaining = pickerLease.remainingMillis()
        val ownsPicker = request != null && request.uri == null && request.identity == opened?.identity
        if (!ownsPicker || remaining == 0L || deviceLocked()) {
            lock()
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
            )
        pickerTimeout?.cancel()
        pickerTimeout =
            viewModelScope.launch {
                delay(remaining)
                lock()
            }
    }

    private fun deviceLocked(): Boolean =
        getApplication<Application>().getSystemService(KeyguardManager::class.java)?.isDeviceLocked != false

    private fun finishPickerHandoff() {
        if (pickerSuspended && (pickerLease.remainingMillis() == 0L || deviceLocked())) lock()
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
                operationJob = viewModelScope.launch { processPendingTransfer(opened, token, account) }
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
                is PendingVaultTransfer.Upload -> uploadPicked(opened, request, token, account)
                is PendingVaultTransfer.Export -> exportWithCleanup(opened, request, token, account)
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

    private suspend fun exportWithCleanup(
        opened: VaultRouteSession,
        request: PendingVaultTransfer.Export,
        token: Long,
        account: String,
    ) {
        var completed = false
        try {
            exportPicked(opened, request, token, account)
            completed = true
        } finally {
            if (!completed) discardIncompleteExport(requireNotNull(request.uri))
        }
    }

    private suspend fun discardIncompleteExport(uri: Uri) {
        withContext(NonCancellable + ioDispatcher) {
            // ACTION_CREATE_DOCUMENT creates a new destination. A provider may refuse deletion;
            // the export error deliberately still tells the user to check for an incomplete copy.
            runCatching { DocumentsContract.deleteDocument(getApplication<Application>().contentResolver, uri) }
        }
    }

    private suspend fun uploadPicked(
        opened: VaultRouteSession,
        request: PendingVaultTransfer.Upload,
        token: Long,
        account: String,
    ) {
        val uri = requireNotNull(request.uri)
        val parentPath = opened.decodeDirectoryPath(request.encryptedParentPath)
        val resolver = getApplication<Application>().contentResolver
        val metadata = withContext(ioDispatcher) { readDocumentMetadata(resolver, uri) }
        if (!isCurrent(token, account) || session !== opened || request.identity != opened.identity) return
        opened.list(parentPath)
        withContext(ioDispatcher) {
            resolver.openInputStream(uri)?.use { source ->
                opened.upload(
                    parentPath,
                    metadata.name,
                    source,
                    metadata.size?.takeIf { it >= 0 } ?: -1L,
                    metadata.mimeType,
                )
            } ?: error("The selected source is unavailable.")
        }
        publishTransferListing(opened, parentPath, token, account)
    }

    // Reject identity, size and destination failures before exposing plaintext.
    @Suppress("ThrowsCount")
    private suspend fun exportPicked(
        opened: VaultRouteSession,
        request: PendingVaultTransfer.Export,
        token: Long,
        account: String,
    ) {
        val uri = requireNotNull(request.uri)
        val parentPath = opened.decodeDirectoryPath(request.encryptedParentPath)
        val source =
            opened.list(parentPath).singleOrNull {
                it.id == request.id &&
                    it.encryptedPath == request.encryptedPath &&
                    request.strongETag.isStrongVaultETag() &&
                    it.strongETag == request.strongETag &&
                    it.strongETag.isStrongVaultETag() &&
                    it.size == request.observedSize &&
                    !it.isFolder
            } ?: throw VaultSourceChangedException()
        if (!isCurrent(token, account) || session !== opened || request.identity != opened.identity) return
        val resolver = getApplication<Application>().contentResolver
        withContext(ioDispatcher) {
            resolver.openOutputStream(uri, "wt")?.use { sink ->
                opened.download(source, sink, Long.MAX_VALUE)
            } ?: error("The selected destination is unavailable.")
        }
        publishTransferListing(opened, parentPath, token, account)
    }

    private suspend fun publishTransferListing(
        opened: VaultRouteSession,
        path: String,
        token: Long,
        account: String,
    ) {
        if (!isCurrent(token, account) || session !== opened) return
        val entries = opened.list(path)
        if (isCurrent(token, account) && session === opened) {
            mutableState.value =
                mutableState.value.copy(
                    entries = presentEntries(entries),
                    currentPath = path,
                    loading = false,
                    error = null,
                )
        }
    }

    // Destination errors become UI state; each stale account/session/route dimension is rejected.
    @Suppress("TooGenericExceptionCaught", "ReturnCount", "ComplexCondition")
    fun loadDestinationFolders(path: String) {
        val opened = session ?: return
        val account = accountId ?: return
        if (mutableState.value.mode != VaultRouteMode.CONTENTS || mutableState.value.loading) return
        destinationJob?.cancel()
        val request = ++destinationGeneration
        val revision = mutableState.value.lockRevision
        mutableState.value =
            mutableState.value.copy(
                destinationPickerPath = path,
                destinationPickerEntries = emptyList(),
                destinationPickerLoading = true,
                destinationPickerError = null,
            )
        destinationJob =
            viewModelScope.launch {
                try {
                    val destinations = opened.list(path).filter { !it.isVaultRoot }
                    if (request != destinationGeneration ||
                        session !== opened ||
                        accountId != account ||
                        mutableState.value.lockRevision != revision
                    ) {
                        return@launch
                    }
                    mutableState.value =
                        mutableState.value.copy(
                            destinationPickerLoading = false,
                            destinationPickerEntries =
                                destinations.map {
                                    VaultRouteEntry(
                                        it.id + "\u0000" + it.path,
                                        it.name,
                                        it.path,
                                        it.isFolder,
                                        false,
                                        it.size,
                                        it.contentType,
                                        displaySize = if (it.isFolder) null else encryptedPlaintextSize(it.size),
                                    )
                                },
                        )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (request == destinationGeneration && session === opened) {
                        mutableState.value =
                            mutableState.value.copy(
                                destinationPickerLoading = false,
                                destinationPickerError = VaultRouteError.CONTENTS,
                            )
                    }
                }
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

    private fun clearDestinationPicker() {
        destinationGeneration++
        destinationJob?.cancel()
        destinationJob = null
        mutableState.value =
            mutableState.value.copy(
                destinationPickerPath = null,
                destinationPickerEntries = emptyList(),
                destinationPickerLoading = false,
                destinationPickerError = null,
            )
    }

    private suspend fun revalidateActionSource(
        opened: VaultRouteSession,
        expected: VaultFolder,
    ): VaultFolder = matchActionSource(opened.list(expected.path.substringBeforeLast('/', "")), expected)

    private fun matchActionSource(
        entries: List<VaultFolder>,
        expected: VaultFolder,
    ): VaultFolder =
        entries.singleOrNull {
            it.id == expected.id &&
                it.encryptedPath == expected.encryptedPath &&
                it.strongETag == expected.strongETag &&
                it.size == expected.size &&
                it.isFolder == expected.isFolder
        } ?: throw VaultSourceChangedException()

    fun onEntryAction(
        id: String,
        action: VaultEntryAction,
        value: String?,
    ) {
        val presented = findEntry(id) ?: return
        when (action) {
            VaultEntryAction.KEEP_OFFLINE -> runSessionMutation { opened -> opened.pinOffline(presented.remote) }
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
    private fun runSessionMutation(block: suspend (VaultRouteSession) -> Unit) {
        if (mutableState.value.loading || mutableState.value.mode != VaultRouteMode.CONTENTS) return
        val opened = session ?: return
        if (opened.isOffline) return
        val account = accountId ?: return
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        operationJob =
            viewModelScope.launch {
                try {
                    block(opened)
                    if (!isCurrent(token, account) || session !== opened) return@launch
                    val entries = opened.list(mutableState.value.currentPath)
                    if (isCurrent(token, account) && session === opened) {
                        mutableState.value = mutableState.value.copy(entries = presentEntries(entries), loading = false)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        VaultRouteError.OPERATION,
                        VaultFailureContext(token, account, lockOnRevocation = true),
                    )
                }
            }
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
                opened.upload(path, name, source, size, mime)
                check(valid())
            }
        }
    }

    fun keepDirectoryOffline() {
        val path = mutableState.value.currentPath
        runSessionMutation { it.pinOfflineDirectory(path) }
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

    /** A management lease is valid only for this unlocked root and route revision. */
    @Suppress("ReturnCount", "ComplexCondition") // Reject every stale lease dimension before exposing a target.
    fun managementTarget(expectedLockRevision: Long): VaultLocation? {
        val current = mutableState.value
        val selected = target ?: return null
        val opened = session ?: return null
        if (!routeActive ||
            current.mode != VaultRouteMode.CONTENTS ||
            current.loading ||
            opened.isOffline ||
            current.lockRevision != expectedLockRevision ||
            current.currentPath.isNotEmpty() ||
            opened.identity != selected.expectedIdentity()
        ) {
            return null
        }
        return selected.location.copy(
            title = selected.title,
            kind =
                if (selected.location.kind == VaultLocationKind.SPACE_VAULT) {
                    VaultLocationKind.SPACE_VAULT
                } else {
                    VaultLocationKind.FOLDER_VAULT
                },
            remoteVaultId = selected.remoteVaultId,
            vaultPath = selected.vaultPath,
            isVaultRoot = true,
        )
    }

    fun isManagementUnlocked(
        location: VaultLocation,
        expectedLockRevision: Long,
    ): Boolean {
        val current = managementTarget(expectedLockRevision) ?: return false
        return current.accountId == location.accountId &&
            current.canonicalServer == location.canonicalServer &&
            current.driveId == location.driveId &&
            current.remoteVaultId == location.remoteVaultId &&
            current.sourceRootId == location.sourceRootId &&
            current.vaultPath == location.vaultPath &&
            current.rootWebDavUrl == location.rootWebDavUrl &&
            current.kind == location.kind
    }

    @Suppress("ReturnCount") // Updates require a live identity; metadata persistence is best effort.
    fun managedSpaceChanged(
        location: VaultLocation,
        expectedLockRevision: Long,
    ) {
        if (!isManagementUnlocked(location, expectedLockRevision)) return
        val selected = target ?: return
        target = selected.copy(location = selected.location.copy(title = location.title), title = location.title)
        mutableState.value = mutableState.value.copy(selectedTitle = location.title)
        val identity = session?.identity ?: return
        runCatching {
            when (preferenceStatus(identity)) {
                VaultPreferenceStatus.REMEMBERED ->
                    biometricPreferences.remember(
                        identity,
                        location.title,
                        targetKind(),
                    )
                VaultPreferenceStatus.DECLINED -> biometricPreferences.decline(identity, location.title, targetKind())
                null -> Unit
            }
        }
    }

    @Suppress("TooGenericExceptionCaught") // Cleanup errors retain a locked route; cancellation is rethrown.
    fun managedSpaceLifecycleChanged(
        expectedLockRevision: Long,
        onComplete: () -> Unit,
    ) {
        val location = managementTarget(expectedLockRevision) ?: return
        val identity = session?.identity ?: return
        lock()
        val token = generation
        viewModelScope.launch {
            try {
                repository.removeOffline(identity)
                if (isCurrent(token, location.accountId)) onComplete()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                reportFailure(failure, VaultRouteError.OPERATION, VaultFailureContext(token, location.accountId))
            }
        }
    }

    @Suppress("ComplexCondition") // Only a live online root may expose server management.
    fun showRootActions() {
        if (session != null &&
            session?.isOffline == false &&
            mutableState.value.mode == VaultRouteMode.CONTENTS &&
            mutableState.value.currentPath.isEmpty()
        ) {
            mutableState.value = mutableState.value.copy(rootActionsVisible = true)
        }
    }

    fun dismissRootActions() {
        mutableState.value = mutableState.value.copy(rootActionsVisible = false)
    }

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

    // Explicit guards reject stale operations; provider failures become safe UI states.
    @Suppress("ReturnCount", "TooGenericExceptionCaught")
    fun renameRoot(
        name: String,
        expectedLockRevision: Long,
    ) {
        if (!isCurrentRootAction(expectedLockRevision)) return
        val opened = session ?: return
        val account = accountId ?: return
        val selected = target ?: return
        if (selected.location.kind != VaultLocationKind.FOLDER_VAULT || name.isBlank()) return
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(loading = true, rootActionsVisible = false, error = null)
        operationJob =
            viewModelScope.launch {
                try {
                    val changed = opened.renameVaultRoot(name)
                    repository.removeOffline(opened.identity)
                    if (!isCurrent(token, account)) return@launch
                    closeSession()
                    clearSensitiveState()
                    target = VaultTarget(changed, changed.vaultPath, changed.title, changed.remoteVaultId)
                    currentTargetIdentity =
                        VaultIdentity(
                            changed.accountId,
                            changed.canonicalServer,
                            changed.driveId,
                            changed.remoteVaultId,
                        )
                    directLocation = changed
                    val enrollment = enrollmentStatus(requireNotNull(currentTargetIdentity))
                    when (preferenceStatus(requireNotNull(currentTargetIdentity))) {
                        VaultPreferenceStatus.REMEMBERED ->
                            runCatching {
                                biometricPreferences.remember(
                                    requireNotNull(currentTargetIdentity),
                                    changed.title,
                                    targetKind(),
                                )
                            }
                        VaultPreferenceStatus.DECLINED ->
                            runCatching {
                                biometricPreferences.decline(
                                    requireNotNull(currentTargetIdentity),
                                    changed.title,
                                    targetKind(),
                                )
                            }
                        null -> Unit
                    }
                    mutableState.value =
                        VaultRouteState(
                            mode = VaultRouteMode.UNLOCK,
                            selectedLocation = presentLocation(changed),
                            selectedTitle = changed.title,
                            biometricEnrolled = enrollment.first,
                            biometricNeedsForget = enrollment.second,
                            lockRevision = mutableState.value.lockRevision + 1,
                        )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    lockAfterAmbiguousRootChange(failure, token, account)
                }
            }
    }

    // Explicit guards reject stale operations; provider failures become safe UI states.
    @Suppress("ReturnCount", "TooGenericExceptionCaught")
    fun deleteRoot(expectedLockRevision: Long) {
        if (!isCurrentRootAction(expectedLockRevision)) return
        val opened = session ?: return
        val account = accountId ?: return
        val selected = target ?: return
        if (selected.location.kind != VaultLocationKind.FOLDER_VAULT) return
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(loading = true, rootActionsVisible = false, error = null)
        operationJob =
            viewModelScope.launch {
                try {
                    opened.deleteVaultRoot()
                    repository.removeOffline(opened.identity)
                    if (!isCurrent(token, account)) return@launch
                    val deletedIdentity = opened.identity
                    closeSession()
                    clearSensitiveState()
                    target = null
                    currentTargetIdentity = null
                    showCatalog()
                    if (!clearDeletedVaultAccess(deletedIdentity)) {
                        pendingDeletedVaultCleanup = deletedIdentity
                        mutableState.value = mutableState.value.copy(error = VaultRouteError.BIOMETRIC_CLEANUP)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    lockAfterAmbiguousRootChange(failure, token, account)
                }
            }
    }

    private fun isCurrentRootAction(expectedLockRevision: Long): Boolean =
        routeActive &&
            !mutableState.value.loading &&
            mutableState.value.lockRevision == expectedLockRevision &&
            mutableState.value.mode == VaultRouteMode.CONTENTS &&
            mutableState.value.currentPath.isEmpty() &&
            mutableState.value.selectedLocation?.kind == VaultLocationKindUi.FOLDER_VAULT &&
            session?.isOffline == false &&
            target?.location?.kind == VaultLocationKind.FOLDER_VAULT

    private fun lockAfterAmbiguousRootChange(
        failure: Throwable,
        token: Long,
        account: String,
    ) {
        if (!isCurrent(token, account)) return
        val classified = classifyVaultFailure(failure, VaultRouteError.OPERATION)
        closeSession()
        clearSensitiveState()
        val selected = target
        val enrollment = selected?.let { enrollmentStatus(it.expectedIdentity()) }
        mutableState.value =
            VaultRouteState(
                mode = if (selected == null) VaultRouteMode.CATALOG else VaultRouteMode.UNLOCK,
                selectedLocation = selected?.let { presentLocation(it.location) },
                selectedTitle = selected?.title,
                error = if (classified.requiresVaultRelock()) classified else VaultRouteError.OPERATION,
                biometricEnrolled = enrollment?.first ?: false,
                biometricNeedsForget = enrollment?.second ?: false,
                lockRevision = mutableState.value.lockRevision + 1,
            )
    }

    // A failed local cleanup remains retryable without repeating the remote deletion.
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun clearDeletedVaultAccess(identity: VaultIdentity): Boolean =
        try {
            biometricStore.forget(identity)
            biometricPreferences.remove(identity)
            true
        } catch (_: Exception) {
            false
        }

    private fun retryDeletedVaultCleanup(): Boolean {
        val identity = pendingDeletedVaultCleanup ?: return false
        if (clearDeletedVaultAccess(identity)) {
            pendingDeletedVaultCleanup = null
            mutableState.value = mutableState.value.copy(error = null)
        } else {
            mutableState.value = mutableState.value.copy(error = VaultRouteError.BIOMETRIC_CLEANUP)
        }
        return true
    }

    private fun folderRequest(id: String): VaultContentsRequest? {
        val entry = findEntry(id)?.route?.takeIf { it.isFolder } ?: return null
        return contentsRequest(entry.path)
    }

    /** Decoded thumbnails stay in memory and become unusable when their originating lease changes. */
    @Suppress("TooGenericExceptionCaught") // Optional thumbnails must not block directory browsing.
    suspend fun loadThumbnail(id: String): ByteArray? {
        val request = thumbnailRequest(id) ?: return null
        var bytes: ByteArray? = null
        return try {
            withContext(ioDispatcher) {
                bytes =
                    thumbnailMutex.withLock {
                        if (!isThumbnailCurrent(request)) return@withLock null
                        if (!isVaultVideo(request.entry.route.name) &&
                            request.entry.route.size <= IN_MEMORY_PREVIEW_BYTES
                        ) {
                            return@withLock request.session.preview(request.entry.remote)
                        }
                        streamedThumbnail(request)
                    }
            }
            val ready = bytes
            if (ready != null && ready.size <= MAX_VAULT_IMAGE_BYTES && isThumbnailCurrent(request)) {
                ready.also { bytes = null }
            } else {
                null
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        } finally {
            bytes?.fill(0)
        }
    }

    private suspend fun streamedThumbnail(request: ThumbnailRequest): ByteArray? {
        val backing = EncryptedPreviewBacking.create(getApplication()) { isThumbnailCurrent(request) }
        return try {
            request.session.download(request.entry.remote, backing.outputStream(), Long.MAX_VALUE)
            backing.seal()
            val bitmap =
                if (isVaultVideo(request.entry.route.name)) {
                    loadEncryptedVideoThumbnail(getApplication(), backing)
                } else {
                    decodeBoundedBitmap(backing, maximumDimension = 256)
                }
            bitmap?.let(::encodeThumbnail)
        } finally {
            backing.close()
        }
    }

    private fun encodeThumbnail(bitmap: Bitmap): ByteArray? =
        try {
            ByteArrayOutputStream().use { output ->
                if (bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)) output.toByteArray() else null
            }
        } finally {
            bitmap.recycle()
        }

    @Suppress("ReturnCount") // Reject unsupported images before decrypting or allocating thumbnail data.
    private fun thumbnailRequest(id: String): ThumbnailRequest? {
        if (mutableState.value.mode != VaultRouteMode.CONTENTS || mutableState.value.loading) return null
        val entry = findEntry(id) ?: return null
        if (entry.route.isFolder ||
            (previewKind(entry.route.name) != VaultPreviewKind.IMAGE && !isVaultVideo(entry.route.name))
        ) {
            return null
        }
        val opened = session ?: return null
        val account = accountId ?: return null
        return ThumbnailRequest(opened, account, generation, entry)
    }

    private fun isThumbnailCurrent(request: ThumbnailRequest): Boolean =
        isCurrent(request.token, request.account) &&
            session === request.session &&
            findEntry(request.entry.route.id) === request.entry &&
            !mutableState.value.loading

    private data class ThumbnailRequest(
        val session: VaultRouteSession,
        val account: String,
        val token: Long,
        val entry: PresentedVaultFolder,
    )

    @Suppress("ReturnCount") // Reject invalid or stale preview requests before starting any work.
    private fun previewRequest(id: String, token: Long): VaultPreviewRequest? {
        val presented = findEntry(id) ?: return null
        val entry = presented.route
        if (entry.isFolder) return null
        val kind = previewKind(entry.name)
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
    // Early exits reject stale or unsupported previews before publication.
    @Suppress("TooGenericExceptionCaught", "ReturnCount", "CyclomaticComplexMethod")
    private suspend fun loadPreview(request: VaultPreviewRequest) {
        var bytes: ByteArray? = null
        var backing: EncryptedPreviewBacking? = null
        try {
            val memoryThreshold =
                if (request.kind == VaultPreviewKind.TEXT) {
                    minOf(IN_MEMORY_PREVIEW_BYTES, MAX_VAULT_EDIT_TEXT_BYTES)
                } else {
                    IN_MEMORY_PREVIEW_BYTES
                }
            if (request.remoteEntry.size > memoryThreshold) {
                backing =
                    EncryptedPreviewBacking.create(getApplication()) {
                        accountId == request.account && session === request.session && routeActive
                    }
                request.session.download(request.remoteEntry, backing.outputStream(), Long.MAX_VALUE)
                backing.seal()
                if (!isCurrent(request.token, request.account) || session !== request.session) return
                loadedPreviewRequest = request
                mutableState.value =
                    mutableState.value.copy(
                        loading = false,
                        error = null,
                        preview =
                            VaultRoutePreview(
                                request.title,
                                ByteArray(0),
                                request.kind,
                                editable =
                                    request.kind == VaultPreviewKind.TEXT &&
                                        !request.session.isOffline &&
                                        request.remoteEntry.strongETag != null,
                                backing = backing,
                            ),
                    )
                backing = null
                return
            }
            bytes = request.session.preview(request.remoteEntry)
            if (
                bytes.size > request.maximumBytes ||
                !isCurrent(request.token, request.account) ||
                session !== request.session
            ) {
                bytes.fill(0)
                return
            }
            val kind = request.kind.decodedKind(bytes.size)
            if (kind == VaultPreviewKind.UNSUPPORTED) {
                bytes.fill(0)
                bytes = null
                mutableState.value =
                    mutableState.value.copy(loading = false, error = VaultRouteError.PREVIEW, preview = null)
                return
            }
            loadedPreviewRequest = request
            mutableState.value =
                mutableState.value.copy(
                    loading = false,
                    error = null,
                    preview =
                        VaultRoutePreview(
                            request.title,
                            bytes,
                            kind,
                            editable =
                                kind == VaultPreviewKind.TEXT &&
                                    !request.session.isOffline &&
                                    request.remoteEntry.strongETag != null,
                        ),
                )
            bytes = null
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            reportFailure(
                failure,
                VaultRouteError.PREVIEW,
                VaultFailureContext(request.token, request.account, lockOnRevocation = true),
            )
        } finally {
            bytes?.fill(0)
            backing?.close()
        }
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    private fun loadContents(
        opened: VaultRouteSession,
        path: String,
        token: Long,
        account: String,
    ) {
        operationJob =
            viewModelScope.launch {
                try {
                    val entries = opened.list(path)
                    if (isCurrent(token, account) && session === opened) {
                        mutableState.value =
                            mutableState.value.copy(
                                entries = presentEntries(entries),
                                currentPath = path,
                                loading = false,
                                error = null,
                            )
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        VaultRouteError.CONTENTS,
                        VaultFailureContext(token, account, lockOnRevocation = true),
                    )
                }
            }
    }

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

    fun lock() {
        invalidateRequests()
        closeSession()
        clearSensitiveState()
        currentSource = null
        val currentTarget = target
        mutableState.value =
            mutableState.value.copy(
                mode = if (currentTarget != null) VaultRouteMode.UNLOCK else VaultRouteMode.CATALOG,
                selectedLocation = currentTarget?.let { presentLocation(it.location) },
                selectedTitle = currentTarget?.title,
                browseTitle = null,
                currentPath = "",
                entries = emptyList(),
                loading = false,
                error = null,
                canEnrollBiometric = false,
                biometricOfferPending = false,
                preview = null,
                lockRevision = mutableState.value.lockRevision + 1,
            )
        if (currentTarget != null) {
            val enrollment = enrollmentStatus(currentTarget.expectedIdentity())
            mutableState.value =
                mutableState.value.copy(
                    biometricEnrolled = enrollment.first,
                    biometricNeedsForget = enrollment.second,
                )
        }
    }

    fun retry() {
        if (retryDeletedVaultCleanup()) return
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

    fun prepareBiometricUnlock(): Cipher? {
        val identity = currentTargetIdentity ?: return null
        return try {
            pendingBiometricIdentity = identity
            biometricStore.prepareUnlock(identity)
        } catch (_: Exception) {
            mutableState.value =
                mutableState.value.copy(
                    error = VaultRouteError.BIOMETRIC,
                    biometricEnrolled = true,
                    biometricNeedsForget = true,
                )
            null
        }
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    @Suppress("TooGenericExceptionCaught")
    fun completeBiometricUnlock(cipher: Cipher?) {
        val identity = pendingBiometricIdentity
        val selected = target
        val account = accountId
        pendingBiometricIdentity = null
        if (!isCurrentBiometricUnlock(identity, selected, account, cipher)) {
            identity?.let { runCatching { biometricStore.cancelUnlock(it) } }
            return
        }
        checkNotNull(identity)
        checkNotNull(selected)
        checkNotNull(account)
        checkNotNull(cipher)
        val material =
            try {
                biometricStore.completeUnlock(identity, cipher)
            } catch (_: Exception) {
                runCatching { biometricStore.cancelUnlock(identity) }
                mutableState.value =
                    mutableState.value.copy(
                        error = VaultRouteError.BIOMETRIC_SETUP,
                        biometricEnrolled = true,
                        biometricNeedsForget = true,
                    )
                return
            }
        val token = nextGeneration()
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        val biometricJob =
            viewModelScope.launch {
                var unlocked: VaultRouteSession? = null
                try {
                    unlocked =
                        repository.unlockWithKeyMaterial(account, selected.location, selected.vaultPath, material)
                    if (!isCurrent(token, account)) {
                        unlocked.close()
                        return@launch
                    }
                    installSession(unlocked, selected, token, account, captureKeyMaterial = false)
                    unlocked = null
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        VaultRouteError.UNLOCK,
                        VaultFailureContext(token, account, lockOnRevocation = true),
                    )
                } finally {
                    material.fill(0)
                    unlocked?.close()
                }
            }
        biometricJob.invokeOnCompletion { material.fill(0) }
        operationJob = biometricJob
    }

    fun cancelBiometricUnlock() {
        val identity = pendingBiometricIdentity
        pendingBiometricIdentity = null
        if (identity != null) runCatching { biometricStore.cancelUnlock(identity) }
    }

    fun prepareBiometricEnrollment(): Cipher? {
        val identity = session?.identity
        return if (identity == null || verifiedKeyMaterial == null) {
            mutableState.value = mutableState.value.copy(error = VaultRouteError.BIOMETRIC)
            null
        } else {
            try {
                pendingEnrollmentIdentity = identity
                biometricStore.prepareEnrollment(identity)
            } catch (_: Exception) {
                mutableState.value = mutableState.value.copy(error = VaultRouteError.BIOMETRIC)
                null
            }
        }
    }

    fun acceptBiometricOffer() {
        val currentState = mutableState.value
        val canEnroll = session != null && verifiedKeyMaterial != null
        if (!routeActive || !currentState.biometricOfferPending || !canEnroll) {
            return
        }
        mutableState.value = currentState.copy(biometricOfferPending = false)
        maybeOpenRootActions()
    }

    fun declineBiometricOffer() {
        val currentState = mutableState.value
        val identity = session?.identity ?: return
        if (!routeActive || !currentState.biometricOfferPending) return
        runCatching {
            biometricPreferences.decline(identity, currentState.selectedTitle.orEmpty(), targetKind())
        }
        clearVerifiedKeyMaterial()
        mutableState.value = currentState.copy(biometricOfferPending = false, canEnrollBiometric = false)
        maybeOpenRootActions()
    }

    @Suppress("TooGenericExceptionCaught") // Provider errors become sanitized categories, never raw text.
    fun completeBiometricEnrollment(cipher: Cipher?) {
        val identity = pendingEnrollmentIdentity
        val material = verifiedKeyMaterial
        pendingEnrollmentIdentity = null
        if (!isCurrentBiometricEnrollment(identity, cipher, material)) {
            identity?.let { runCatching { biometricStore.cancelEnrollment(it) } }
            clearVerifiedKeyMaterial()
            if (routeActive) mutableState.value = mutableState.value.copy(canEnrollBiometric = false)
            return
        }
        checkNotNull(identity)
        checkNotNull(cipher)
        checkNotNull(material)
        var enrolled = false
        try {
            biometricStore.completeEnrollment(identity, cipher, material)
            enrolled = true
        } catch (failure: Exception) {
            runCatching { biometricStore.cancelEnrollment(identity) }
            mutableState.value =
                mutableState.value.copy(
                    error = VaultRouteError.BIOMETRIC_SETUP,
                    biometricDiagnostic = enrollmentDiagnostic(failure),
                    canEnrollBiometric = false,
                )
        } finally {
            material.fill(0)
            verifiedKeyMaterial = null
        }
        if (enrolled) {
            runCatching {
                biometricPreferences.remember(identity, mutableState.value.selectedTitle.orEmpty(), targetKind())
            }
            mutableState.value =
                mutableState.value.copy(
                    biometricEnrolled = true,
                    biometricNeedsForget = false,
                    canEnrollBiometric = false,
                    biometricOfferPending = false,
                    error = null,
                )
        }
    }

    fun cancelBiometricEnrollment() {
        val identity = pendingEnrollmentIdentity
        pendingEnrollmentIdentity = null
        if (identity != null) runCatching { biometricStore.cancelEnrollment(identity) }
        clearVerifiedKeyMaterial()
        mutableState.value = mutableState.value.copy(canEnrollBiometric = false)
    }

    fun forgetBiometric(expectedLockRevision: Long) {
        val currentState = mutableState.value
        val identity =
            if (routeActive && currentState.lockRevision == expectedLockRevision) {
                currentTargetIdentity ?: target?.expectedIdentity()
            } else {
                null
            } ?: return
        try {
            biometricStore.forget(identity)
            biometricPreferences.remove(identity)
        } catch (_: Exception) {
            mutableState.value = mutableState.value.copy(error = VaultRouteError.BIOMETRIC)
            return
        }
        clearVerifiedKeyMaterial()
        mutableState.value =
            mutableState.value.copy(
                biometricEnrolled = false,
                biometricNeedsForget = false,
                canEnrollBiometric = false,
                biometricOfferPending = false,
                error = null,
            )
    }

    private fun isCurrentBiometricUnlock(
        identity: VaultIdentity?,
        selected: VaultTarget?,
        account: String?,
        cipher: Cipher?,
    ): Boolean {
        val hasAuthenticationContext = account != null && cipher != null
        if (identity == null || selected == null || !hasAuthenticationContext) return false
        return routeActive && accountId == account && identity == selected.expectedIdentity()
    }

    private fun isCurrentBiometricEnrollment(
        identity: VaultIdentity?,
        cipher: Cipher?,
        material: ByteArray?,
    ): Boolean {
        if (identity == null || cipher == null || material == null) return false
        return routeActive && identity == session?.identity
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

    private fun enrollmentStatus(identity: VaultIdentity): Pair<Boolean, Boolean> =
        try {
            biometricStore.hasEnrollment(identity) to false
        } catch (_: Exception) {
            true to true
        }

    private fun preferenceStatus(identity: VaultIdentity): VaultPreferenceStatus? =
        runCatching { biometricPreferences.status(identity) }.getOrNull()

    private fun targetKind(): VaultPreferenceTargetKind =
        if (target?.location?.kind == VaultLocationKind.SPACE_VAULT) {
            VaultPreferenceTargetKind.SPACE
        } else {
            VaultPreferenceTargetKind.FOLDER
        }

    private fun previewKind(name: String): VaultPreviewKind {
        val extension = name.substringAfterLast('.', "").lowercase()
        return when (extension) {
            "txt", "md", "csv", "json", "xml", "yaml", "yml", "log", "ini", "toml" -> VaultPreviewKind.TEXT
            "png", "jpg", "jpeg", "webp", "gif", "bmp", "heic", "heif", "avif" -> VaultPreviewKind.IMAGE
            "pdf" -> VaultPreviewKind.PDF
            else -> VaultPreviewKind.UNSUPPORTED
        }
    }

    private fun VaultTarget.expectedIdentity() =
        VaultIdentity(
            accountId = location.accountId,
            canonicalServer = location.canonicalServer,
            driveId = location.driveId,
            remoteVaultId = remoteVaultId,
        )

    private fun isCurrent(
        token: Long,
        account: String,
    ): Boolean = routeActive && accountId == account && generation == token

    private fun nextGeneration(): Long {
        generation += 1
        operationJob?.cancel()
        operationJob = null
        pendingBiometricIdentity?.let { runCatching { biometricStore.cancelUnlock(it) } }
        pendingBiometricIdentity = null
        pendingEnrollmentIdentity?.let { runCatching { biometricStore.cancelEnrollment(it) } }
        pendingEnrollmentIdentity = null
        return generation
    }

    private fun invalidateRequests() {
        generation += 1
        catalogJob?.cancel()
        catalogJob = null
        operationJob?.cancel()
        operationJob = null
        pendingBiometricIdentity?.let { runCatching { biometricStore.cancelUnlock(it) } }
        pendingBiometricIdentity = null
        pendingEnrollmentIdentity?.let { runCatching { biometricStore.cancelEnrollment(it) } }
        pendingEnrollmentIdentity = null
    }

    private fun closeSession() {
        clearDestinationPicker()
        pickerTimeout?.cancel()
        pickerTimeout = null
        pickerLease.clear()
        pickerSuspended = false
        session?.close()
        session = null
    }

    private fun clearPreview() {
        loadedPreviewRequest = null
        mutableState.value = mutableState.value.copy(previewSaving = false, previewSaveError = null)
        mutableState.value.preview?.let { preview ->
            preview.bytes.fill(0)
            preview.backing?.close()
        }
    }

    private fun clearVerifiedKeyMaterial() {
        verifiedKeyMaterial?.fill(0)
        verifiedKeyMaterial = null
    }

    private fun clearSensitiveState() {
        pendingTransferSource = null
        mutableState.value = mutableState.value.copy(transferConflict = null)
        closeSession()
        clearPreview()
        clearVerifiedKeyMaterial()
        presentedEntries.clear()
    }

    override fun onCleared() {
        leaveRoute()
        super.onCleared()
    }

    private data class VaultTarget(
        val location: VaultLocation,
        val vaultPath: String,
        val title: String,
        val remoteVaultId: String,
    )

    private data class PresentedVaultFolder(
        val route: VaultRouteEntry,
        val remote: VaultFolder,
    )
}

interface VaultRouteRepository {
    suspend fun offlineLocations(accountId: String): List<VaultLocation> = emptyList()

    suspend fun removeOffline(identity: VaultIdentity) = Unit

    suspend fun locations(accountId: String): List<VaultLocation>

    suspend fun folders(
        accountId: String,
        location: VaultLocation,
        path: String,
    ): List<VaultFolder>

    suspend fun unlock(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        password: CharArray,
    ): VaultRouteSession

    suspend fun unlockWithKeyMaterial(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        keyMaterial: ByteArray,
    ): VaultRouteSession
}

interface VaultRouteSession {
    fun offlineAvailable(entry: VaultFolder): Boolean? = if (isOffline) true else null

    val isOffline: Boolean get() = false

    suspend fun pinOffline(entry: VaultFolder): Unit = unsupportedVaultMutation()

    suspend fun pinOfflineDirectory(path: String): Unit = unsupportedVaultMutation()

    val identity: VaultIdentity

    suspend fun list(path: String): List<VaultFolder>

    suspend fun preview(entry: VaultFolder): ByteArray

    suspend fun exportVerifiedKeyMaterial(): ByteArray

    suspend fun encodeDirectoryPath(plainPath: String): String = plainPath

    suspend fun decodeDirectoryPath(encryptedRelativePath: String): String = encryptedRelativePath

    suspend fun createFolder(
        parentPath: String,
        name: String,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun delete(entry: VaultFolder): Unit = unsupportedVaultMutation()

    suspend fun rename(
        entry: VaultFolder,
        newName: String,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun move(
        entry: VaultFolder,
        destinationPath: String,
        newName: String = entry.name,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun copy(
        entry: VaultFolder,
        destinationPath: String,
        newName: String = entry.name,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun upload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun replaceText(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long,
    ): Long = unsupportedVaultMutation()

    suspend fun renameVaultRoot(newName: String): VaultLocation = unsupportedVaultMutation()

    suspend fun deleteVaultRoot(): Unit = unsupportedVaultMutation()

    fun close()
}

private fun <T> unsupportedVaultMutation(): T = throw UnsupportedOperationException("Vault operation is unavailable.")

interface VaultBiometricKeyStore {
    fun hasEnrollment(identity: VaultIdentity): Boolean

    fun prepareEnrollment(identity: VaultIdentity): Cipher

    fun completeEnrollment(
        identity: VaultIdentity,
        cipher: Cipher,
        keyMaterial: ByteArray,
    )

    fun cancelEnrollment(identity: VaultIdentity)

    fun prepareUnlock(identity: VaultIdentity): Cipher

    fun completeUnlock(
        identity: VaultIdentity,
        cipher: Cipher,
    ): ByteArray

    fun cancelUnlock(identity: VaultIdentity)

    fun forget(identity: VaultIdentity)
}

internal interface VaultOfferPreferences {
    fun status(identity: VaultIdentity): VaultPreferenceStatus?

    fun remember(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    )

    fun decline(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    )

    fun remove(identity: VaultIdentity)
}

private class AndroidVaultRouteRepository(
    application: Application,
) : VaultRouteRepository {
    private val repository = VaultRepository(application)
    private val offline = VaultOfflineStore(application)

    override suspend fun offlineLocations(accountId: String) = offline.locations(accountId)

    override suspend fun removeOffline(identity: VaultIdentity) {
        offline.remove(identity)
    }

    override suspend fun locations(accountId: String) = repository.locations(accountId)

    override suspend fun folders(
        accountId: String,
        location: VaultLocation,
        path: String,
    ) = repository.folders(accountId, location, path)

    override suspend fun unlock(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        password: CharArray,
    ): VaultRouteSession =
        if (target.offlineOnly) {
            AndroidOfflineVaultRouteSession(requireNotNull(offline.openWithPassword(accountId, target, password)))
        } else {
            AndroidVaultRouteSession(repository.unlock(accountId, target, vaultPath, password), offline)
        }

    override suspend fun unlockWithKeyMaterial(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        keyMaterial: ByteArray,
    ): VaultRouteSession =
        if (target.offlineOnly) {
            AndroidOfflineVaultRouteSession(requireNotNull(offline.openWithKeyMaterial(accountId, target, keyMaterial)))
        } else {
            AndroidVaultRouteSession(
                repository.unlockWithKeyMaterial(accountId, target, vaultPath, keyMaterial),
                offline,
            )
        }
}

private class AndroidVaultRouteSession(
    private val session: VaultSession,
    private val offline: VaultOfflineStore,
) : VaultRouteSession {
    override suspend fun pinOffline(entry: VaultFolder) = session.pinOffline(offline, entry)

    override suspend fun pinOfflineDirectory(path: String) = session.pinOfflineDirectory(offline, path)

    override val identity get() = session.identity

    private var savedFiles: List<VaultFolder>? = null

    override fun offlineAvailable(entry: VaultFolder): Boolean? =
        if (entry.isFolder) {
            null
        } else {
            savedFiles?.any {
                it.encryptedPath == entry.encryptedPath && it.strongETag == entry.strongETag
            }
        }

    @Suppress("TooGenericExceptionCaught") // Optional status cannot block live encrypted browsing.
    override suspend fun list(path: String): List<VaultFolder> {
        val entries = session.list(path)
        savedFiles =
            try {
                session.offlineFiles(offline, path)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null
            }
        return entries
    }

    override suspend fun preview(entry: VaultFolder) = session.preview(entry)

    override suspend fun exportVerifiedKeyMaterial() = session.exportVerifiedKeyMaterial()

    override suspend fun encodeDirectoryPath(plainPath: String) = session.encodeDirectoryPath(plainPath)

    override suspend fun decodeDirectoryPath(encryptedRelativePath: String) =
        session.decodeDirectoryPath(encryptedRelativePath)

    override suspend fun createFolder(
        parentPath: String,
        name: String,
    ) = session.createFolder(parentPath, name)

    override suspend fun delete(entry: VaultFolder) = session.delete(entry)

    override suspend fun rename(
        entry: VaultFolder,
        newName: String,
    ) = session.rename(entry, newName)

    override suspend fun move(
        entry: VaultFolder,
        destinationPath: String,
        newName: String,
    ) = session.move(entry, destinationPath, newName)

    override suspend fun copy(
        entry: VaultFolder,
        destinationPath: String,
        newName: String,
    ) = session.copy(entry, destinationPath, newName)

    override suspend fun upload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ) = session.upload(parentPath, name, source, size, mimeType)

    override suspend fun replaceText(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ): VaultFolder =
        session.upload(
            parentPath = entry.path.trim('/').substringBeforeLast('/', ""),
            name = entry.name,
            source = source,
            size = size,
            mimeType = entry.contentType,
            overwrite = entry,
        )

    override suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long,
    ) = session.download(entry, sink, maxPlaintextBytes)

    override suspend fun renameVaultRoot(newName: String) = session.renameVaultRoot(newName)

    override suspend fun deleteVaultRoot() = session.deleteVaultRoot()

    override fun close() {
        savedFiles = null
        session.close()
    }
}

private class AndroidVaultBiometricKeyStore(
    private val store: VaultKeyStore,
) : VaultBiometricKeyStore {
    override fun hasEnrollment(identity: VaultIdentity) = store.hasEnrollment(identity)

    override fun prepareEnrollment(identity: VaultIdentity) = store.prepareEnrollment(identity)

    override fun completeEnrollment(
        identity: VaultIdentity,
        cipher: Cipher,
        keyMaterial: ByteArray,
    ) = store.completeEnrollment(identity, cipher, keyMaterial)

    override fun cancelEnrollment(identity: VaultIdentity) = store.cancelEnrollment(identity)

    override fun prepareUnlock(identity: VaultIdentity) = store.prepareUnlock(identity)

    override fun completeUnlock(
        identity: VaultIdentity,
        cipher: Cipher,
    ) = store.completeUnlock(identity, cipher)

    override fun cancelUnlock(identity: VaultIdentity) = store.cancelUnlock(identity)

    override fun forget(identity: VaultIdentity) = store.forget(identity)
}

private class AndroidVaultOfferPreferences(
    application: Application,
) : VaultOfferPreferences {
    private val preferences = VaultPreferences(application)

    override fun status(identity: VaultIdentity) = preferences.status(identity)

    override fun remember(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    ) = preferences.remember(identity, title, targetKind)

    override fun decline(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    ) = preferences.decline(identity, title, targetKind)

    override fun remove(identity: VaultIdentity) = preferences.remove(identity)
}

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte -> "%02x".format(byte) }

private const val IN_MEMORY_PREVIEW_BYTES = 8 * 1024 * 1024
private const val MAX_VAULT_IMAGE_BYTES = 8 * 1024 * 1024

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
        else ->
            when (failure.toOpenCloudError()) {
                OpenCloudError.Connectivity, OpenCloudError.Timeout -> VaultRouteError.CONNECTION
                OpenCloudError.Trust -> VaultRouteError.SECURE_CONNECTION
                OpenCloudError.InvalidResponse -> VaultRouteError.SERVER_RESPONSE
                OpenCloudError.AuthenticationRequired, OpenCloudError.ClientRegistrationRequired ->
                    VaultRouteError.AUTHENTICATION
                OpenCloudError.AccessDenied -> VaultRouteError.ACCESS_DENIED
                OpenCloudError.PreconditionFailed, OpenCloudError.NotFound ->
                    if (classifyVaultIdentity) VaultRouteError.VAULT_CHANGED else fallback
                else -> fallback
            }
    }

private class VaultSourceChangedException : IllegalStateException("The selected source changed.")

private class VaultIdentityChangedException : IllegalStateException("Vault identity changed during unlock.")

private fun VaultRouteError.requiresVaultRelock(): Boolean =
    this == VaultRouteError.AUTHENTICATION ||
        this == VaultRouteError.ACCESS_DENIED ||
        this == VaultRouteError.VAULT_CHANGED

private data class VaultContentsRequest(
    val session: VaultRouteSession,
    val path: String,
    val account: String,
)

private data class VaultFailureContext(
    val token: Long,
    val account: String,
    val lockOnRevocation: Boolean = false,
    val classifyVaultIdentity: Boolean = true,
)

private data class VaultPreviewRequest(
    val session: VaultRouteSession,
    val account: String,
    val remoteEntry: VaultFolder,
    val title: String,
    val kind: VaultPreviewKind,
    val maximumBytes: Long,
    val token: Long,
)

private sealed class PendingVaultTransfer(
    open val identity: VaultIdentity,
    open val uri: Uri?,
) {
    data class Upload(
        override val identity: VaultIdentity,
        val encryptedParentPath: String,
        override val uri: Uri? = null,
    ) : PendingVaultTransfer(identity, uri)

    data class Export(
        override val identity: VaultIdentity,
        val encryptedParentPath: String,
        val id: String,
        val encryptedPath: String,
        val strongETag: String?,
        val observedSize: Long,
        override val uri: Uri? = null,
    ) : PendingVaultTransfer(identity, uri)

    fun withUri(value: Uri): PendingVaultTransfer =
        when (this) {
            is Upload -> copy(uri = value)
            is Export -> copy(uri = value)
        }
}

private data class VaultDocumentMetadata(
    val name: String,
    val size: Long?,
    val mimeType: String?,
)

private fun String?.isStrongVaultETag(): Boolean = this != null && length >= 2 && startsWith('"') && endsWith('"')

private fun readDocumentMetadata(
    resolver: ContentResolver,
    uri: Uri,
): VaultDocumentMetadata {
    var name: String? = null
    var size: Long? = null
    resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { cursor ->
        if (cursor.moveToFirst()) {
            val nameColumn = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameColumn >= 0) name = cursor.getString(nameColumn)
            val sizeColumn = cursor.getColumnIndex(OpenableColumns.SIZE)
            if (sizeColumn >= 0 && !cursor.isNull(sizeColumn)) size = cursor.getLong(sizeColumn)
        }
    }
    return VaultDocumentMetadata(
        name = name?.takeIf(String::isNotBlank) ?: "upload",
        size = size,
        mimeType = resolver.getType(uri),
    )
}

private fun VaultPreviewKind.decodedKind(size: Int): VaultPreviewKind =
    if (size >= 0) this else VaultPreviewKind.UNSUPPORTED

private class AndroidOfflineVaultRouteSession(
    private val session: VaultOfflineSession,
) : VaultRouteSession {
    override val isOffline = true
    override val identity get() = session.identity

    override suspend fun list(path: String) = session.list(path)

    override suspend fun preview(entry: VaultFolder) = session.preview(entry)

    override suspend fun exportVerifiedKeyMaterial() = session.exportVerifiedKeyMaterial()

    override suspend fun encodeDirectoryPath(plainPath: String) = session.encodeDirectoryPath(plainPath)

    override suspend fun decodeDirectoryPath(encryptedRelativePath: String) =
        session.decodeDirectoryPath(encryptedRelativePath)

    override suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long,
    ) = session.download(entry, sink, maxPlaintextBytes)

    override fun close() = session.close()
}

/** Process-local callback lease: no scanner destination or key is serialized. */
internal class VaultScanLease(
    val destinationLabel: String,
    val isValid: () -> Boolean,
    val upload: suspend (String, InputStream, Long, String) -> Unit,
)

/** Preserve extensions; choose the first free numbered sibling without overwriting. */
internal fun numberedEncryptedName(
    name: String,
    folder: Boolean,
    existing: Set<String>,
): String {
    val dot = if (folder) -1 else name.lastIndexOf('.').takeIf { it > 0 } ?: -1
    val stem = if (dot < 0) name else name.substring(0, dot)
    val extension = if (dot < 0) "" else name.substring(dot)
    return generateSequence(1) { it + 1 }.map { "$stem ($it)$extension" }.first { it !in existing }
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

private fun isVaultVideo(name: String): Boolean =
    name.substringAfterLast('.', "").lowercase(java.util.Locale.ROOT) in
        setOf("mp4", "m4v", "mov", "webm", "mkv", "3gp", "avi", "mpeg", "mpg")
