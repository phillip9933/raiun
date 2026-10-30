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
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.VaultDeviceRememberException
import eu.opencloud.android.next.core.security.VaultDeviceRememberOutcomeUnknownException
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultKeyStore
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultPreferences
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.security.VaultRememberChoice
import eu.opencloud.android.next.core.security.VaultUnlockPolicy
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.VaultBoundaryEndpoint
import eu.opencloud.android.next.core.sync.VaultDirectorySnapshot
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
import eu.opencloud.android.next.core.sync.asBoundaryEntry
import eu.opencloud.android.next.core.sync.completePendingOfflineDownloads
import eu.opencloud.android.next.core.sync.completePendingOfflineGroups
import eu.opencloud.android.next.core.sync.enqueueBackgroundOfflineDownload
import eu.opencloud.android.next.core.sync.enqueueBackgroundOfflineGroup
import eu.opencloud.android.next.core.sync.enqueueBackgroundReplacement
import eu.opencloud.android.next.core.sync.enqueueBackgroundUpload
import eu.opencloud.android.next.core.sync.withCancellableVaultUploadSource
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.map
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

    private var accountId: String? = null
    private var routeActive = false
    private var openRootMenuAfterUnlock = false
    private var generation = 0L
    private var catalogJob: Job? = null
    private var operationJob: Job? = null
    private var offlineCompletionJob: Job? = null
    private var session: VaultRouteSession? = null
    private var directory: VaultRouteDirectorySnapshot? = null
    private val previousDirectoryOffsets = mutableListOf<Long>()
    private var showHidden = false
    private var loadedPreviewRequest: VaultPreviewRequest? = null
    private var pendingTransferSource: VaultFolder? = null
    private var currentSource: VaultLocation? = null
    private var discoveryReturn: DiscoveryReturn? = null
    private var target: VaultTarget? = null
    private var currentTargetIdentity: VaultIdentity? = null
    private var phoneSessionIssueIdentity: VaultIdentity? = null
    private var verifiedKeyMaterial: ByteArray? = null
    private var provenAccountSnapshot: Any? = null
    private var provenCredentialPermit: (() -> Boolean)? = null
    private var pendingBiometricIdentity: VaultIdentity? = null
    private var explicitDeviceForgetIdentity: VaultIdentity? = null
    private var explicitDeviceForgetJob: Job? = null
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
    private var destinationDirectory: VaultRouteDirectorySnapshot? = null
    private val destinationPreviousOffsets = mutableListOf<Long>()
    private var destinationSources: Map<String, PresentedVaultFolder> = emptyMap()
    private var destinationSource: PresentedVaultFolder? = null

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
        val phoneSessionIssueCode = mutableState.value.phoneSessionIssueCode
        routeActive = false
        accountId = null
        invalidateRequests()
        clearSensitiveState()
        currentSource = null
        discoveryReturn = null
        sourceLocations = emptyMap()
        directLocation = null
        pendingTransfer = null
        target = null
        currentTargetIdentity = null
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
        discoveryReturn = null
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
        val selectedTarget = VaultTarget(folderLocation, entry.path, entry.name, presented.remote.id)
        target = selectedTarget
        showPasswordUnlock(selectedTarget)
    }

    fun showCatalog() {
        discoveryReturn = null
        invalidateRequests()
        clearSensitiveState()
        currentSource = null
        target = null
        currentTargetIdentity = null
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
                    val snapshot = repository.unlockAccountSnapshot(account)
                    val credentialPermit = repository.unlockCredentialPermit(account)
                    unlocked = repository.unlock(account, selected.location, selected.vaultPath, password)
                    if (!isCurrent(token, account)) {
                        unlocked.close()
                        return@launch
                    }
                    installSession(
                        unlocked,
                        selected,
                        token,
                        account,
                        phoneAdmission =
                            PhoneUnlockAdmission(
                                snapshot,
                                credentialPermit,
                                captureKeyMaterial = true,
                            ),
                    )
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

    @Suppress("ReturnCount") // Independent phone admission checks surround one-shot key export.
    private suspend fun installSession(
        opened: VaultRouteSession,
        selected: VaultTarget,
        token: Long,
        account: String,
        phoneAdmission: PhoneUnlockAdmission = PhoneUnlockAdmission(),
    ) {
        var capturedMaterial: ByteArray? = null
        var firstDirectory: OpenedVaultDirectory? = null
        try {
            if (opened.identity != selected.expectedIdentity()) throw VaultIdentityChangedException()
            firstDirectory = openFirstDirectory(opened, "")
            if (!keepCurrentRouteSession(opened, token, account, phoneAdmission.reusedKey)) return
            requireCurrentReuse(account, phoneAdmission)
            capturedMaterial = captureVerifiedMaterial(opened, phoneAdmission.captureKeyMaterial)
            if (capturedMaterial == null && phoneAdmission.provenBiometricMaterial != null) {
                capturedMaterial = phoneAdmission.provenBiometricMaterial.copyOf()
            }
            if (!keepCurrentRouteSession(opened, token, account, phoneAdmission.reusedKey)) return
            val phoneSessionIssueCode = rememberProvenPhoneUnlock(opened, account, capturedMaterial, phoneAdmission)
            updatePhoneSessionIssue(opened.identity, phoneAdmission, phoneSessionIssueCode)
            if (keepCurrentRouteSession(opened, token, account, phoneAdmission.reusedKey)) {
                val installed =
                    publishOpenedSession(
                        SessionPublication(
                            opened,
                            selected,
                            token,
                            account,
                            phoneAdmission,
                            checkNotNull(firstDirectory),
                            capturedMaterial,
                        ),
                    )
                if (installed) {
                    firstDirectory = null
                    capturedMaterial = null
                }
            }
        } finally {
            firstDirectory?.snapshot?.close()
            capturedMaterial?.fill(0)
        }
    }

    private suspend fun publishOpenedSession(publication: SessionPublication): Boolean {
        val opened = publication.opened
        val selected = publication.selected
        val phoneAdmission = publication.phoneAdmission
        val capturedMaterial = publication.capturedMaterial
        val offers = determinePhoneUnlockOffers(opened, phoneAdmission, capturedMaterial)
        val visibleDirectory = currentVisibilityDirectory(opened, publication.initialDirectory)
        if (!keepCurrentRouteSession(opened, publication.token, publication.account, phoneAdmission.reusedKey)) {
            if (visibleDirectory !== publication.initialDirectory) visibleDirectory.snapshot.close()
            return false
        }
        val entries = visibleDirectory.entries
        closeSession()
        clearVerifiedKeyMaterial()
        session = opened
        directory = visibleDirectory.snapshot
        previousDirectoryOffsets.clear()
        val page = VaultDirectoryPageState(0, visibleDirectory.snapshot.totalCount, entries.size, false)
        currentTargetIdentity = opened.identity
        verifiedKeyMaterial = offers.pendingMaterial
        provenAccountSnapshot = phoneAdmission.accountSnapshot
        provenCredentialPermit = phoneAdmission.credentialPermit
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
                directoryPage = page,
                loading = false,
                error = null,
                biometricEnrolled = offers.enrollment.first,
                biometricNeedsForget = offers.enrollment.second,
                canEnrollBiometric = offers.legacyBiometricOffer,
                biometricOfferPending = offers.offerPending,
                phoneRememberOffer = offers.phoneRememberOffer,
                allowAutomaticBiometric =
                    mutableState.value.allowAutomaticBiometric || phoneAdmission.captureKeyMaterial,
                rootActionsVisible = mutableState.value.rootActionsVisible,
                preview = null,
            )
        maybeOpenRootActions()
        processPendingTransfer(opened, publication.token, publication.account)
        observePendingOffline(opened, publication.account)
        return true
    }

    private suspend fun determinePhoneUnlockOffers(
        opened: VaultRouteSession,
        phoneAdmission: PhoneUnlockAdmission,
        capturedMaterial: ByteArray?,
    ): PhoneUnlockOffers {
        val enrollment = enrollmentStatus(opened.identity)
        val hasFreshMaterial = capturedMaterial != null && phoneAdmission.reusedKey == null
        val (rememberChoice, deviceRememberSupported) =
            withContext(ioDispatcher) {
                runCatching { adapters.deviceRemember.choice(opened.identity) }.getOrNull() to
                    (
                        !VaultUnlockPolicy(getApplication<Application>()).askEveryTime() &&
                            runCatching { adapters.deviceRemember.isSupported() }.getOrDefault(false)
                    )
            }
        val phoneRememberOffer = hasFreshMaterial && deviceRememberSupported && rememberChoice == null
        val legacyBiometricOffer =
            hasFreshMaterial &&
                !deviceRememberSupported &&
                rememberChoice != VaultRememberChoice.DECLINED &&
                !enrollment.first &&
                preferenceStatus(opened.identity) == null
        val offerPending = phoneRememberOffer || legacyBiometricOffer
        val pendingMaterial = if (offerPending) capturedMaterial else null
        if (!offerPending) capturedMaterial?.fill(0)
        return PhoneUnlockOffers(enrollment, phoneRememberOffer, legacyBiometricOffer, offerPending, pendingMaterial)
    }

    private fun updatePhoneSessionIssue(
        identity: VaultIdentity,
        admission: PhoneUnlockAdmission,
        issueCode: String?,
    ) {
        val existing = mutableState.value.phoneSessionIssueCode
        val next =
            when {
                issueCode != null -> issueCode
                admission.reusedKey != null || admission.captureKeyMaterial -> null
                admission.provenBiometricMaterial != null && existing == "US7" -> "US7"
                admission.provenBiometricMaterial != null -> null
                else -> existing
            }
        if (next != existing) {
            phoneSessionIssueIdentity = if (next == null) null else identity
            mutableState.value = mutableState.value.copy(phoneSessionIssueCode = next)
        }
    }

    private data class PhoneUnlockAdmission(
        val accountSnapshot: Any? = null,
        val credentialPermit: () -> Boolean = { false },
        val provenBiometricMaterial: ByteArray? = null,
        val reusedKey: VaultDeviceRememberKey? = null,
        val rememberBinding: VaultRememberBinding? = null,
        val captureKeyMaterial: Boolean = false,
    )

    private data class PhoneRememberRequest(
        val opened: VaultRouteSession,
        val identity: VaultIdentity,
        val account: String,
        val material: ByteArray,
        val accountSnapshot: Any,
        val credentialPermit: () -> Boolean,
        val token: Long,
        val lockRevision: Long,
    )

    private data class SessionPublication(
        val opened: VaultRouteSession,
        val selected: VaultTarget,
        val token: Long,
        val account: String,
        val phoneAdmission: PhoneUnlockAdmission,
        val initialDirectory: OpenedVaultDirectory,
        val capturedMaterial: ByteArray?,
    )

    private data class PhoneUnlockOffers(
        val enrollment: Pair<Boolean, Boolean>,
        val phoneRememberOffer: Boolean,
        val legacyBiometricOffer: Boolean,
        val offerPending: Boolean,
        val pendingMaterial: ByteArray?,
    )

    private sealed interface PhoneRestoreLookup {
        data object Unavailable : PhoneRestoreLookup

        data object RevocationFailed : PhoneRestoreLookup

        data class Ready(
            val key: VaultDeviceRememberKey,
            val snapshot: Any,
            val binding: VaultRememberBinding,
            val credentialPermit: () -> Boolean,
        ) : PhoneRestoreLookup
    }

    private suspend fun keepCurrentRouteSession(
        opened: VaultRouteSession,
        token: Long,
        account: String,
        reusedKey: VaultDeviceRememberKey? = null,
    ): Boolean {
        val keyCurrent = reusedKey == null || withContext(ioDispatcher) { reusedKey.isCurrent() }
        val current = isCurrent(token, account) && keyCurrent
        if (!current) opened.close()
        return current
    }

    private suspend fun requireCurrentReuse(
        account: String,
        admission: PhoneUnlockAdmission,
    ) {
        val key = admission.reusedKey ?: return
        val accountStillCurrent =
            withContext(ioDispatcher) { repository.unlockAccountSnapshot(account) == admission.accountSnapshot }
        val bindingStillCurrent =
            admission.rememberBinding == null ||
                withContext(ioDispatcher) { repository.rememberBinding(account) } == admission.rememberBinding
        if (!withContext(ioDispatcher) { key.isCurrent() } || !accountStillCurrent || !bindingStillCurrent) {
            throw VaultIdentityChangedException()
        }
    }

    private suspend fun captureVerifiedMaterial(
        opened: VaultRouteSession,
        capture: Boolean,
    ): ByteArray? {
        if (!capture) return null
        return try {
            opened.exportVerifiedKeyMaterial()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        }
    }

    private suspend fun rememberProvenPhoneUnlock(
        opened: VaultRouteSession,
        account: String,
        capturedMaterial: ByteArray?,
        admission: PhoneUnlockAdmission,
    ): String? {
        val sameAccount = accountSnapshotIsCurrent(account, admission.accountSnapshot)
        if (admission.reusedKey != null && !sameAccount) throw VaultIdentityChangedException()
        val material = capturedMaterial ?: admission.provenBiometricMaterial
        val binding = resolveRememberedBinding(account, material, sameAccount, admission.rememberBinding)
        val acceptedRememberMode = isAcceptedRememberMode(opened.identity, account, binding)
        val diagnose = admission.provenBiometricMaterial != null && acceptedRememberMode && admission.reusedKey == null
        return phoneSessionIssue(admission, sameAccount, material, diagnose)
    }

    private suspend fun accountSnapshotIsCurrent(
        account: String,
        snapshot: Any?,
    ): Boolean = snapshot != null && withContext(ioDispatcher) { repository.unlockAccountSnapshot(account) == snapshot }

    private suspend fun resolveRememberedBinding(
        account: String,
        material: ByteArray?,
        sameAccount: Boolean,
        previousBinding: VaultRememberBinding?,
    ): VaultRememberBinding? =
        if (sameAccount && material != null) {
            withContext(ioDispatcher) { repository.rememberBinding(account) }
        } else {
            previousBinding
        }

    private suspend fun isAcceptedRememberMode(
        identity: VaultIdentity,
        account: String,
        binding: VaultRememberBinding?,
    ): Boolean {
        val modeAndStoreSupported =
            withContext(ioDispatcher) {
                !VaultUnlockPolicy(getApplication<Application>()).askEveryTime() &&
                    runCatching { adapters.deviceRemember.isSupported() }.getOrDefault(false)
            }
        val remembered =
            withContext(
                ioDispatcher,
            ) { runCatching { adapters.deviceRemember.hasRemembered(identity) }.getOrDefault(false) }
        val bindingCurrent =
            binding != null && withContext(ioDispatcher) { repository.rememberBinding(account) == binding }
        return modeAndStoreSupported && remembered && bindingCurrent
    }

    private fun phoneSessionIssue(
        admission: PhoneUnlockAdmission,
        sameAccount: Boolean,
        material: ByteArray?,
        diagnose: Boolean,
    ): String? =
        when {
            !diagnose -> null
            !sameAccount -> "US6"
            material == null -> "US3"
            !runCatching(admission.credentialPermit).getOrDefault(false) -> "US2"
            else -> null
        }

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

    private fun showPasswordUnlock(selected: VaultTarget) {
        val token = nextGeneration()
        closeSession()
        clearVerifiedKeyMaterial()
        clearPreview()
        val expectedIdentity = selected.expectedIdentity()
        val phoneSessionIssueCode =
            if (phoneSessionIssueIdentity == null || phoneSessionIssueIdentity == expectedIdentity) {
                mutableState.value.phoneSessionIssueCode
            } else {
                phoneSessionIssueIdentity = null
                null
            }
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
                phoneSessionIssueCode = phoneSessionIssueCode,
                biometricEnrolled = enrollment.first,
                biometricNeedsForget = enrollment.second,
                canEnrollBiometric = false,
                biometricOfferPending = false,
                phoneRememberOffer = false,
                allowAutomaticBiometric = true,
                preview = null,
                lockRevision = mutableState.value.lockRevision + 1,
            )
        tryPhoneSessionUnlock(selected, token)
    }

    @Suppress("TooGenericExceptionCaught") // Failed optional reuse falls back to the normal unlock surface.
    private fun tryPhoneSessionUnlock(selected: VaultTarget, token: Long) {
        val account = accountId ?: return
        // Keep the biometric prompt ineligible until this bounded lookup/revalidation finishes.
        mutableState.value = mutableState.value.copy(loading = true)
        operationJob =
            viewModelScope.launch {
                var key: VaultDeviceRememberKey? = null
                var opened: VaultRouteSession? = null
                var attemptedCachedKeyProof = false
                try {
                    val lookup = resolvePhoneRestore(selected.expectedIdentity(), account, token)
                    if (lookup is PhoneRestoreLookup.RevocationFailed) {
                        showPhoneRestoreRevocationFailure(selected.expectedIdentity(), token, account)
                        return@launch
                    }
                    val ready = lookup as? PhoneRestoreLookup.Ready ?: return@launch
                    key = ready.key
                    if (!isCurrent(token, account)) return@launch
                    attemptedCachedKeyProof = true
                    opened =
                        repository.unlockWithKeyMaterial(
                            account,
                            selected.location,
                            selected.vaultPath,
                            ready.key.material,
                        )
                    if (!isCurrent(token, account)) return@launch
                    installSession(
                        opened,
                        selected,
                        token,
                        account,
                        phoneAdmission =
                            PhoneUnlockAdmission(
                                accountSnapshot = ready.snapshot,
                                credentialPermit = ready.credentialPermit,
                                reusedKey = ready.key,
                                rememberBinding = ready.binding,
                            ),
                    )
                    opened = null
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (attemptedCachedKeyProof && isCurrent(token, account)) {
                        phoneSessionIssueIdentity = selected.expectedIdentity()
                        mutableState.value = mutableState.value.copy(phoneSessionIssueCode = "US7")
                    }
                } finally {
                    opened?.close()
                    key?.close()
                    if (isCurrent(token, account) && mutableState.value.mode == VaultRouteMode.UNLOCK) {
                        mutableState.value = mutableState.value.copy(loading = false)
                    }
                }
            }
    }

    private suspend fun resolvePhoneRestore(
        identity: VaultIdentity,
        account: String,
        token: Long,
    ): PhoneRestoreLookup {
        val priorFence = VaultDeviceRememberRevocations.await(identity)
        if (priorFence == false) {
            return if (retryFailedDeviceForget(identity)) {
                PhoneRestoreLookup.Unavailable
            } else {
                PhoneRestoreLookup.RevocationFailed
            }
        }
        return loadPhoneRestoreCandidate(identity, account, token)
    }

    private suspend fun loadPhoneRestoreCandidate(
        identity: VaultIdentity,
        account: String,
        token: Long,
    ): PhoneRestoreLookup {
        val snapshot = withContext(ioDispatcher) { repository.unlockAccountSnapshot(account) }
        val restoreAllowed = phoneRestoreAllowed()
        val remembered =
            restoreAllowed &&
                withContext(ioDispatcher) {
                    runCatching { adapters.deviceRemember.hasRemembered(identity) }.getOrDefault(false)
                }
        val binding = if (remembered) withContext(ioDispatcher) { repository.rememberBinding(account) } else null
        val credentialPermit = if (binding != null) repository.unlockCredentialPermit(account) else null
        val restoredKey =
            if (binding != null && credentialPermit != null) {
                withContext(ioDispatcher) { adapters.deviceRemember.restore(identity, binding, credentialPermit) }
            } else {
                null
            }
        val currentKey =
            restoredKey?.takeIf {
                isCurrent(token, account) && withContext(ioDispatcher) { it.isCurrent() }
            }
        if (currentKey == null) restoredKey?.close()
        return currentKey?.let { safeKey ->
            val currentSnapshot = snapshot
            val currentBinding = binding
            val currentPermit = credentialPermit
            if (currentSnapshot != null && currentBinding != null && currentPermit != null) {
                PhoneRestoreLookup.Ready(safeKey, currentSnapshot, currentBinding, currentPermit)
            } else {
                safeKey.close()
                null
            }
        } ?: PhoneRestoreLookup.Unavailable
    }

    private suspend fun phoneRestoreAllowed(): Boolean =
        withContext(ioDispatcher) {
            !VaultUnlockPolicy(getApplication<Application>()).askEveryTime() &&
                runCatching { adapters.deviceRemember.isSupported() }.getOrDefault(false)
        }

    private fun showPhoneRestoreRevocationFailure(
        identity: VaultIdentity,
        token: Long,
        account: String,
    ) {
        if (!isCurrent(token, account)) return
        phoneSessionIssueIdentity = identity
        mutableState.value =
            mutableState.value.copy(
                loading = false,
                error = VaultRouteError.PHONE_LOCK_FAILED,
                phoneSessionIssueCode = "US8",
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
        val current = revalidateActionSource(request.session, request.remote)
        if (!isCurrent(request.token, request.account) || session !== request.session) return null
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
                            request.session.queueReplacement(request.remoteEntry, it, total)
                        }
                    }
                    if (!isCurrent(token, request.account) || session !== request.session) return@launch
                    mutableState.value =
                        mutableState.value.copy(queuedUploadCount = mutableState.value.queuedUploadCount + 1)
                    clearPreview()
                    mutableState.value = mutableState.value.copy(preview = null, loading = true, error = null)
                    loadContents(request.session, mutableState.value.currentPath, token, request.account)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    if (isCurrent(token, request.account) && session === request.session) {
                        // Admission may have committed before scheduling/delivery was interrupted.
                        // Retain the draft but require a fresh version before another replacement.
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
            tryPhoneSessionUnlock(selected, nextGeneration())
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
        if (!isCurrentTransferSession(opened, request.identity, token, account)) return
        verifyUploadDirectory(opened, parentPath)
        if (!isCurrentTransferSession(opened, request.identity, token, account)) return
        mutableState.value = mutableState.value.copy(preparingUpload = true)
        try {
            withContext(ioDispatcher) {
                withCancellableVaultUploadSource(getApplication(), uri, adapters.uploadPollReady) { source ->
                    opened.queueUpload(
                        parentPath,
                        metadata.name,
                        source,
                        metadata.size?.takeIf { it >= 0 } ?: -1L,
                        metadata.mimeType,
                    )
                }
            }
            if (isCurrent(token, account) && session === opened) {
                mutableState.value =
                    mutableState.value.copy(queuedUploadCount = mutableState.value.queuedUploadCount + 1)
            }
        } finally {
            if (isCurrent(token, account) && session === opened) {
                mutableState.value = mutableState.value.copy(preparingUpload = false)
            }
        }
        publishTransferListing(opened, parentPath, token, account)
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
            findFreshDirectoryEntry(opened, parentPath) {
                it.id == request.id &&
                    it.encryptedPath == request.encryptedPath &&
                    request.strongETag.isStrongVaultETag() &&
                    it.strongETag == request.strongETag &&
                    it.strongETag.isStrongVaultETag() &&
                    it.size == request.observedSize &&
                    !it.isFolder
            }
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
        replaceDirectory(opened, path, token, account)
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
        val selected = findEntry(id) ?: destinationSources[id] ?: return null
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
        operationJob =
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
            }
    }

    fun beginDestinationPicker(
        id: String,
        path: String,
    ) {
        val selected = findEntry(id) ?: return
        if (mutableState.value.loading || mutableState.value.mode != VaultRouteMode.CONTENTS) return
        destinationSource = selected
        loadDestinationFolders(path)
    }

    fun loadDestinationFolders(path: String) {
        val request = destinationRequest(path) ?: return
        if (mutableState.value.destinationPickerPath == null) destinationSources = presentedEntries.toMap()
        destinationJob?.cancel()
        closeDestinationDirectory()
        closeDirectory()
        mutableState.value =
            mutableState.value.copy(
                entries = emptyList(),
                destinationPickerPath = path,
                destinationPickerEntries = emptyList(),
                destinationPickerPage = null,
                destinationPickerLoading = true,
                destinationPickerError = null,
            )
        destinationJob = viewModelScope.launch { openDestinationDirectory(request) }
    }

    private data class DestinationRequest(
        val opened: VaultRouteSession,
        val account: String,
        val path: String,
        val revision: Long,
        val lockRevision: Long,
        val routeGeneration: Long,
    )

    private fun destinationRequest(path: String): DestinationRequest? {
        val opened = session
        val account = accountId
        val available = mutableState.value.mode == VaultRouteMode.CONTENTS && !mutableState.value.loading
        if (opened == null || account == null || !available) return null
        return DestinationRequest(
            opened,
            account,
            path,
            ++destinationGeneration,
            mutableState.value.lockRevision,
            generation,
        )
    }

    private fun isCurrentDestination(request: DestinationRequest): Boolean {
        val sessionCurrent = routeActive && session === request.opened && accountId == request.account
        val viewCurrent =
            destinationGeneration == request.revision && mutableState.value.lockRevision == request.lockRevision
        return sessionCurrent && viewCurrent && generation == request.routeGeneration
    }

    @Suppress("TooGenericExceptionCaught") // Destination snapshots close on cancellation and late completion.
    private suspend fun openDestinationDirectory(request: DestinationRequest) {
        var snapshot: VaultRouteDirectorySnapshot? = null
        var adopted = false
        try {
            val exclusion = destinationSource?.remote?.takeIf { it.isFolder }?.path
            snapshot = request.opened.openDirectory(request.path, showHidden, exclusion)
            currentCoroutineContext().ensureActive()
            val entries = snapshot.page(0, VAULT_DIRECTORY_PAGE_SIZE)
            currentCoroutineContext().ensureActive()
            if (!isCurrentDestination(request)) return
            destinationDirectory = snapshot
            adopted = true
            publishDestinationPage(snapshot, entries, 0)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            reportDestinationFailure(request, failure)
        } finally {
            if (!adopted) snapshot?.close()
        }
    }

    fun destinationPage(previous: Boolean) {
        val snapshot = destinationDirectory
        val page = mutableState.value.destinationPickerPage
        if (snapshot == null || page == null || mutableState.value.destinationPickerLoading) return
        val canMove = if (previous) page.hasPrevious else page.hasNext
        if (!canMove) return
        val offset = if (previous) destinationPreviousOffsets.lastOrNull() else page.offset + page.count
        val request = destinationRequest(mutableState.value.destinationPickerPath.orEmpty())
        if (offset != null && request != null) {
            destinationJob?.cancel()
            mutableState.value =
                mutableState.value.copy(destinationPickerEntries = emptyList(), destinationPickerLoading = true)
            destinationJob =
                viewModelScope.launch { loadDestinationPage(request, snapshot, page.offset, offset, previous) }
        }
    }

    @Suppress("TooGenericExceptionCaught") // Page revocation reports safe errors and closes the invalid snapshot.
    private suspend fun loadDestinationPage(
        request: DestinationRequest,
        snapshot: VaultRouteDirectorySnapshot,
        previousOffset: Long,
        offset: Long,
        previous: Boolean,
    ) {
        var delivered = false
        try {
            val entries = snapshot.page(offset, VAULT_DIRECTORY_PAGE_SIZE)
            currentCoroutineContext().ensureActive()
            if (!isCurrentDestination(request) || destinationDirectory !== snapshot) return
            if (previous) {
                destinationPreviousOffsets.removeAt(destinationPreviousOffsets.lastIndex)
            } else {
                destinationPreviousOffsets += previousOffset
            }
            publishDestinationPage(snapshot, entries, offset)
            delivered = true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            reportDestinationFailure(request, failure)
        } finally {
            if (!delivered && destinationDirectory === snapshot) closeDestinationDirectory()
        }
    }

    private fun publishDestinationPage(
        snapshot: VaultRouteDirectorySnapshot,
        entries: List<VaultFolder>,
        offset: Long,
    ) {
        mutableState.value =
            mutableState.value.copy(
                destinationPickerLoading = false,
                destinationPickerError = null,
                destinationPickerPage =
                    VaultDirectoryPageState(
                        offset,
                        snapshot.totalCount,
                        entries.size,
                        destinationPreviousOffsets.isNotEmpty(),
                    ),
                destinationPickerEntries =
                    entries.map { entry ->
                        VaultRouteEntry(
                            entry.id + "\u0000" + entry.path,
                            entry.name,
                            entry.path,
                            entry.isFolder,
                            false,
                            entry.size,
                            entry.contentType,
                            displaySize = if (entry.isFolder) null else encryptedPlaintextSize(entry.size),
                        )
                    },
            )
    }

    private fun reportDestinationFailure(
        request: DestinationRequest,
        failure: Exception,
    ) {
        if (!isCurrentDestination(request)) return
        reportFailure(
            failure,
            VaultRouteError.CONTENTS,
            VaultFailureContext(request.routeGeneration, request.account, lockOnRevocation = true),
        )
        if (session === request.opened) {
            mutableState.value =
                mutableState.value.copy(
                    destinationPickerLoading = false,
                    destinationPickerError = mutableState.value.error ?: VaultRouteError.CONTENTS,
                )
        }
    }

    private fun closeDestinationDirectory() {
        destinationDirectory?.close()
        destinationDirectory = null
        destinationPreviousOffsets.clear()
        mutableState.value = mutableState.value.copy(destinationPickerPage = null)
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
        closeDestinationDirectory()
        destinationSources = emptyMap()
        destinationSource = null
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
                    directory = snapshot
                    previousDirectoryOffsets.addAll(bookmarks)
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
        return findEntry(id) ?: destinationSources[id]?.takeIf { transfer }
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
        operationJob =
            viewModelScope.launch {
                try {
                    block(opened)
                    if (!isCurrent(token, account) || session !== opened) return@launch
                    replaceDirectory(opened, mutableState.value.currentPath, token, account)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    reportFailure(
                        failure,
                        fallback,
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

    /** The first page retains the same root/password proof as the complete validated directory. */
    private suspend fun openFirstDirectory(
        opened: VaultRouteSession,
        path: String,
    ): OpenedVaultDirectory {
        while (true) {
            val visibility = showHidden
            val snapshot = opened.openDirectory(path, visibility)
            var delivered = false
            try {
                currentCoroutineContext().ensureActive()
                val entries = snapshot.page(0, VAULT_DIRECTORY_PAGE_SIZE)
                currentCoroutineContext().ensureActive()
                if (visibility == showHidden) {
                    delivered = true
                    return OpenedVaultDirectory(snapshot, entries, visibility)
                }
            } finally {
                if (!delivered) snapshot.close()
            }
        }
    }

    private suspend fun currentVisibilityDirectory(
        opened: VaultRouteSession,
        first: OpenedVaultDirectory,
    ): OpenedVaultDirectory {
        if (first.showHidden == showHidden) return first
        first.snapshot.close()
        return openFirstDirectory(opened, "")
    }

    private data class OpenedVaultDirectory(
        val snapshot: VaultRouteDirectorySnapshot,
        val entries: List<VaultFolder>,
        val showHidden: Boolean,
    )

    private suspend fun replaceDirectory(
        opened: VaultRouteSession,
        path: String,
        token: Long,
        account: String,
    ) {
        if (!isCurrent(token, account) || session !== opened) return
        closeDirectory()
        val first = openFirstDirectory(opened, path)
        var adopted = false
        try {
            if (!isCurrent(token, account) || session !== opened) return
            directory = first.snapshot
            previousDirectoryOffsets.clear()
            adopted = true
            mutableState.value =
                mutableState.value.copy(
                    entries = presentEntries(first.entries),
                    directoryPage = VaultDirectoryPageState(0, first.snapshot.totalCount, first.entries.size, false),
                    currentPath = path,
                    loading = false,
                    error = null,
                )
        } finally {
            if (!adopted) first.snapshot.close()
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
        closeDirectory()
        mutableState.value = mutableState.value.copy(entries = emptyList(), directoryPage = null)
        operationJob =
            viewModelScope.launch {
                try {
                    replaceDirectory(opened, path, token, account)
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

    fun directoryPage(previous: Boolean) {
        val request = directoryPageRequest(previous) ?: return
        val token = nextGeneration()
        clearPreview()
        presentedEntries.clear()
        mutableState.value =
            mutableState.value.copy(entries = emptyList(), loading = true, preview = null, error = null)
        operationJob = viewModelScope.launch { loadDirectoryPage(request, token) }
    }

    private data class DirectoryPageRequest(
        val opened: VaultRouteSession,
        val snapshot: VaultRouteDirectorySnapshot,
        val account: String,
        val page: VaultDirectoryPageState,
        val offset: Long,
        val previous: Boolean,
    )

    @Suppress("ReturnCount") // Independent session/account/page admission fails closed before replacing action leases.
    private fun directoryPageRequest(previous: Boolean): DirectoryPageRequest? {
        val opened = session ?: return null
        val snapshot = directory ?: return null
        val account = accountId ?: return null
        val page = mutableState.value.directoryPage ?: return null
        val canMove = if (previous) page.hasPrevious else page.hasNext
        if (mutableState.value.loading || !canMove) return null
        val offset = if (previous) previousDirectoryOffsets.lastOrNull() ?: return null else page.offset + page.count
        return DirectoryPageRequest(opened, snapshot, account, page, offset, previous)
    }

    @Suppress("TooGenericExceptionCaught") // Page failure revokes its leases and preserves cancellation.
    private suspend fun loadDirectoryPage(request: DirectoryPageRequest, token: Long) {
        var delivered = false
        try {
            val entries = request.snapshot.page(request.offset, VAULT_DIRECTORY_PAGE_SIZE)
            currentCoroutineContext().ensureActive()
            if (!isCurrent(token, request.account) ||
                session !== request.opened ||
                directory !== request.snapshot
            ) {
                return
            }
            if (request.previous) {
                previousDirectoryOffsets.removeAt(previousDirectoryOffsets.lastIndex)
            } else {
                previousDirectoryOffsets += request.page.offset
            }
            mutableState.value =
                mutableState.value.copy(
                    entries = presentEntries(entries),
                    directoryPage =
                        VaultDirectoryPageState(
                            request.offset,
                            request.snapshot.totalCount,
                            entries.size,
                            previousDirectoryOffsets.isNotEmpty(),
                        ),
                    loading = false,
                    error = null,
                )
            delivered = true
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (isCurrent(token, request.account) && directory === request.snapshot) closeDirectory()
            reportFailure(
                failure,
                VaultRouteError.CONTENTS,
                VaultFailureContext(token, request.account, lockOnRevocation = true),
            )
        } finally {
            if (!delivered && directory === request.snapshot) closeDirectory()
        }
    }

    private fun closeDirectory() {
        directory?.close()
        directory = null
        previousDirectoryOffsets.clear()
        presentedEntries.clear()
        mutableState.value = mutableState.value.copy(directoryPage = null)
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
        val identity = currentTargetIdentity ?: target?.expectedIdentity()
        closeRouteSession()
        if (identity == null) return
        val revocationTicket = VaultDeviceRememberRevocations.begin(identity)
        explicitDeviceForgetIdentity = identity
        mutableState.value =
            mutableState.value.copy(
                loading = true,
                lockingRememberedAccess = true,
                allowAutomaticBiometric = false,
                error = null,
            )
        val previousForget = explicitDeviceForgetJob
        explicitDeviceForgetJob =
            viewModelScope.launch(start = CoroutineStart.UNDISPATCHED) {
                val forgotten =
                    withContext(NonCancellable + ioDispatcher) {
                        previousForget?.join()
                        VaultDeviceRememberRevocations.awaitPredecessor(revocationTicket)
                        runCatching { adapters.deviceRemember.forget(identity) }.isSuccess.also {
                            VaultDeviceRememberRevocations.finish(revocationTicket, it)
                        }
                    }
                if (routeActive &&
                    currentTargetIdentity == identity &&
                    mutableState.value.lockingRememberedAccess
                ) {
                    mutableState.value =
                        mutableState.value.copy(
                            loading = false,
                            lockingRememberedAccess = false,
                            error = if (forgotten) null else VaultRouteError.PHONE_LOCK_FAILED,
                        )
                }
            }
    }

    /** A failed process fence is cleared only by a new durable forget under a replacement ticket. */
    private suspend fun retryFailedDeviceForget(identity: VaultIdentity): Boolean {
        val ticket = VaultDeviceRememberRevocations.begin(identity)
        val forgotten =
            withContext(NonCancellable + ioDispatcher) {
                VaultDeviceRememberRevocations.awaitPredecessor(ticket)
                runCatching { adapters.deviceRemember.forget(identity) }.isSuccess.also {
                    VaultDeviceRememberRevocations.finish(ticket, it)
                }
            }
        return forgotten
    }

    /** Screen-off closes the live route while durable phone consent survives. */
    fun onDeviceLocked() {
        closeRouteSession()
    }

    private fun closeRouteSession() {
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
                phoneRememberOffer = false,
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
                    val snapshot = repository.unlockAccountSnapshot(account)
                    val credentialPermit = repository.unlockCredentialPermit(account)
                    unlocked =
                        repository.unlockWithKeyMaterial(account, selected.location, selected.vaultPath, material)
                    if (!isCurrent(token, account)) {
                        unlocked.close()
                        return@launch
                    }
                    installSession(
                        unlocked,
                        selected,
                        token,
                        account,
                        phoneAdmission =
                            PhoneUnlockAdmission(
                                accountSnapshot = snapshot,
                                credentialPermit = credentialPermit,
                                provenBiometricMaterial = material,
                            ),
                    )
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
        val legacyOffer = currentState.biometricOfferPending && !currentState.phoneRememberOffer
        val verifiedMaterialAvailable = session != null && verifiedKeyMaterial != null
        if (routeActive && legacyOffer && verifiedMaterialAvailable) {
            mutableState.value = currentState.copy(biometricOfferPending = false)
            maybeOpenRootActions()
        }
    }

    fun declineBiometricOffer() {
        val currentState = mutableState.value
        if (!routeActive || !currentState.biometricOfferPending) return
        val identity = session?.identity
        if (identity == null) {
            return
        } else if (currentState.phoneRememberOffer) {
            declinePhoneRememberOffer(identity, currentState)
        } else {
            declineLegacyBiometricOffer(identity, currentState)
        }
    }

    private fun declineLegacyBiometricOffer(
        identity: VaultIdentity,
        currentState: VaultRouteState,
    ) {
        runCatching {
            biometricPreferences.decline(identity, currentState.selectedTitle.orEmpty(), targetKind())
        }
        clearVerifiedKeyMaterial()
        mutableState.value =
            currentState.copy(biometricOfferPending = false, phoneRememberOffer = false, canEnrollBiometric = false)
        maybeOpenRootActions()
    }

    /** Saves only after the user accepts the explicit per-location phone-remember question. */
    fun rememberOnPhone() {
        val request = capturePhoneRememberRequest() ?: return
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        operationJob =
            launchWithOwnedMaterial(viewModelScope, request.material) {
                runPhoneRemember(request)
            }
    }

    private fun capturePhoneRememberRequest(): PhoneRememberRequest? {
        val state = mutableState.value
        val opened = session
        val account = accountId
        val material = verifiedKeyMaterial?.copyOf()
        val snapshot = provenAccountSnapshot
        val permit = provenCredentialPermit
        val canRemember = isPhoneRememberOfferReady(state)
        val hasProof = snapshot != null && permit != null
        val hasContext = opened != null && account != null && material != null
        if (!hasContext || !hasProof || !canRemember) material?.fill(0)
        return if (hasContext && hasProof && canRemember) {
            PhoneRememberRequest(
                opened = requireNotNull(opened),
                identity = requireNotNull(opened).identity,
                account = requireNotNull(account),
                material = requireNotNull(material),
                accountSnapshot = requireNotNull(snapshot),
                credentialPermit = requireNotNull(permit),
                token = generation,
                lockRevision = state.lockRevision,
            )
        } else {
            null
        }
    }

    private fun isPhoneRememberOfferReady(state: VaultRouteState): Boolean {
        val visibleOffer = state.phoneRememberOffer && state.mode == VaultRouteMode.CONTENTS
        return routeActive && visibleOffer && !state.loading
    }

    @Suppress("SwallowedException", "TooGenericExceptionCaught") // Sanitize provider/storage failures.
    private suspend fun runPhoneRemember(request: PhoneRememberRequest) {
        try {
            persistPhoneRemember(request)
            showPhoneRememberSuccess(request)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (unknown: VaultRememberCommitUnknownException) {
            showUnknownPhoneRememberOutcome(request, unknown)
        } catch (changed: VaultIdentityChangedException) {
            showChangedPhoneRememberIdentity(request)
        } catch (_: VaultRememberRevocationException) {
            showPhoneRememberRevocationFailure(request)
        } catch (_: VaultDeviceRememberException) {
            showPhoneRememberFailure(request)
        } catch (_: Exception) {
            showPhoneRememberFailure(request)
        } finally {
            request.material.fill(0)
        }
    }

    private suspend fun persistPhoneRemember(request: PhoneRememberRequest) {
        val identity = request.identity
        if (explicitDeviceForgetIdentity == identity) explicitDeviceForgetJob?.join()
        requirePriorPhoneForgetResolved(identity)
        val binding = validatePhoneRememberOwner(request)
        val admission = withContext(ioDispatcher) { adapters.deviceRemember.begin(identity, binding) }
        val permit = {
            isCurrentPhoneRememberOffer(request) && runCatching(request.credentialPermit).getOrDefault(false)
        }
        requirePhoneRememberAdmission(admission, permit)
        val saved = rememberPhoneMaterial(request, binding, admission, permit)
        requirePhoneRememberSaved(saved)
        verifyPhoneRememberOwner(request, binding, permit)
    }

    private suspend fun requirePriorPhoneForgetResolved(identity: VaultIdentity) {
        if (VaultDeviceRememberRevocations.await(identity) == false && !retryFailedDeviceForget(identity)) {
            throw VaultRememberRevocationException()
        }
    }

    private fun requirePhoneRememberAdmission(
        admission: VaultDeviceRememberAccess.Admission?,
        permit: () -> Boolean,
    ) {
        if (admission == null || !permit()) throw VaultDeviceRememberException()
    }

    private fun requirePhoneRememberSaved(saved: Boolean) {
        if (!saved) throw VaultDeviceRememberException()
    }

    private suspend fun validatePhoneRememberOwner(request: PhoneRememberRequest): VaultRememberBinding {
        val snapshot = withContext(ioDispatcher) { repository.unlockAccountSnapshot(request.account) }
        val binding = withContext(ioDispatcher) { repository.rememberBinding(request.account) }
        if (snapshot != request.accountSnapshot || binding == null || !isCurrentPhoneRememberOffer(request)) {
            throw VaultIdentityChangedException()
        }
        if (!runCatching(request.credentialPermit).getOrDefault(false)) throw VaultIdentityChangedException()
        return binding
    }

    private suspend fun rememberPhoneMaterial(
        request: PhoneRememberRequest,
        binding: VaultRememberBinding,
        admission: VaultDeviceRememberAccess.Admission?,
        permit: () -> Boolean,
    ): Boolean =
        withContext(NonCancellable + ioDispatcher) {
            try {
                adapters.deviceRemember.remember(admission, request.identity, binding, request.material, permit)
            } catch (_: VaultDeviceRememberOutcomeUnknownException) {
                val safelyCleared = runCatching { adapters.deviceRemember.forget(request.identity) }.isSuccess
                if (!safelyCleared) VaultDeviceRememberRevocations.block(request.identity)
                throw VaultRememberCommitUnknownException(safelyCleared)
            }
        }

    private suspend fun verifyPhoneRememberOwner(
        request: PhoneRememberRequest,
        binding: VaultRememberBinding,
        permit: () -> Boolean,
    ) {
        val afterSnapshot = withContext(ioDispatcher) { repository.unlockAccountSnapshot(request.account) }
        val afterBinding = withContext(ioDispatcher) { repository.rememberBinding(request.account) }
        if (!permit() || afterSnapshot != request.accountSnapshot || afterBinding != binding) {
            throw VaultIdentityChangedException()
        }
    }

    private fun showPhoneRememberSuccess(request: PhoneRememberRequest) {
        if (!isCurrentPhoneRememberOffer(request)) return
        clearVerifiedKeyMaterial()
        mutableState.value =
            mutableState.value.copy(
                loading = false,
                error = null,
                biometricOfferPending = false,
                phoneRememberOffer = false,
                canEnrollBiometric = false,
                phoneSessionIssueCode = null,
            )
        maybeOpenRootActions()
    }

    private fun showUnknownPhoneRememberOutcome(
        request: PhoneRememberRequest,
        failure: VaultRememberCommitUnknownException,
    ) {
        if (failure.safelyCleared) {
            if (isCurrentPhoneRememberOffer(request)) {
                mutableState.value =
                    mutableState.value.copy(
                        loading = false,
                        error = VaultRouteError.PHONE_REMEMBER_FAILED,
                        biometricOfferPending = true,
                        phoneRememberOffer = true,
                        canEnrollBiometric = false,
                    )
            }
        } else {
            VaultDeviceRememberRevocations.block(request.identity)
            clearVerifiedKeyMaterial()
            if (routeActive && session === request.opened && currentTargetIdentity == request.identity) {
                mutableState.value =
                    mutableState.value.copy(
                        loading = false,
                        lockingRememberedAccess = false,
                        allowAutomaticBiometric = false,
                        error = VaultRouteError.PHONE_LOCK_FAILED,
                        biometricOfferPending = false,
                        phoneRememberOffer = false,
                        canEnrollBiometric = false,
                    )
            }
        }
    }

    private fun showChangedPhoneRememberIdentity(request: PhoneRememberRequest) {
        if (!isCurrentPhoneRememberOffer(request)) return
        closeRouteSession()
        mutableState.value = mutableState.value.copy(error = VaultRouteError.VAULT_CHANGED)
    }

    private fun showPhoneRememberFailure(request: PhoneRememberRequest) {
        if (!isCurrentPhoneRememberOffer(request)) return
        mutableState.value =
            mutableState.value.copy(
                loading = false,
                error = VaultRouteError.PHONE_REMEMBER_FAILED,
                biometricOfferPending = true,
                phoneRememberOffer = true,
                canEnrollBiometric = false,
            )
    }

    private fun showPhoneRememberRevocationFailure(request: PhoneRememberRequest) {
        if (!isCurrentPhoneRememberOffer(request)) return
        clearVerifiedKeyMaterial()
        mutableState.value =
            mutableState.value.copy(
                loading = false,
                lockingRememberedAccess = false,
                allowAutomaticBiometric = false,
                error = VaultRouteError.PHONE_LOCK_FAILED,
                biometricOfferPending = false,
                phoneRememberOffer = false,
                canEnrollBiometric = false,
            )
    }

    private fun isCurrentPhoneRememberOffer(request: PhoneRememberRequest) =
        isCurrentPhoneRememberOffer(
            request.opened,
            request.identity,
            request.account,
            request.token,
            request.lockRevision,
        )

    private fun declinePhoneRememberOffer(
        identity: VaultIdentity,
        currentState: VaultRouteState,
    ) {
        val opened = session ?: return
        val account = accountId ?: return
        val token = generation
        val lockRevision = currentState.lockRevision
        mutableState.value = currentState.copy(loading = true, error = null)
        operationJob =
            viewModelScope.launch {
                try {
                    withContext(ioDispatcher) { adapters.deviceRemember.decline(identity) }
                    if (isCurrentPhoneRememberOffer(opened, identity, account, token, lockRevision)) {
                        clearVerifiedKeyMaterial()
                        mutableState.value =
                            mutableState.value.copy(
                                loading = false,
                                error = null,
                                biometricOfferPending = false,
                                phoneRememberOffer = false,
                                canEnrollBiometric = false,
                            )
                        maybeOpenRootActions()
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (isCurrentPhoneRememberOffer(opened, identity, account, token, lockRevision)) {
                        mutableState.value = mutableState.value.copy(loading = false, error = VaultRouteError.BIOMETRIC)
                    }
                }
            }
    }

    private fun isCurrentPhoneRememberOffer(
        opened: VaultRouteSession,
        identity: VaultIdentity,
        account: String,
        token: Long,
        lockRevision: Long,
    ): Boolean {
        val current = mutableState.value
        return routeActive &&
            generation == token &&
            accountId == account &&
            session === opened &&
            opened.identity == identity &&
            currentTargetIdentity == identity &&
            current.lockRevision == lockRevision &&
            current.mode == VaultRouteMode.CONTENTS &&
            current.phoneRememberOffer
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
                    phoneRememberOffer = false,
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
                phoneRememberOffer = false,
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
        closeDirectory()
        offlineCompletionJob?.cancel()
        offlineCompletionJob = null
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
        provenAccountSnapshot = null
        provenCredentialPermit = null
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
    /** Immutable non-secret account row; absent adapters opt out of remembered-key restore. */
    suspend fun unlockAccountSnapshot(accountId: String): Any? = null

    /** Durable Room owner scope for device-remember binding; absent adapters opt out safely. */
    suspend fun rememberBinding(accountId: String): VaultRememberBinding? = null

    fun unlockCredentialPermit(accountId: String): () -> Boolean = { false }

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

interface VaultRouteDirectorySnapshot : AutoCloseable {
    val totalCount: Long

    suspend fun page(
        offset: Long = 0,
        limit: Int = VAULT_DIRECTORY_PAGE_SIZE,
    ): List<VaultFolder>

    override fun close()
}

/** Compatibility for small legacy test doubles. Android adapters always override openDirectory. */
private class SmallVaultRouteDirectorySnapshot(
    entries: List<VaultFolder>,
    showHidden: Boolean,
    excludedPath: String?,
) : VaultRouteDirectorySnapshot {
    private val entries =
        entries
            .also { require(it.size <= 256) }
            .filter { showHidden || !it.name.startsWith('.') }
            .filter { excludedPath == null || it.path != excludedPath && !it.path.startsWith(excludedPath + "/") }
            .sortedWith(
                compareBy<VaultFolder> { !it.isFolder }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
                    .thenBy { it.name }
                    .thenBy { it.encryptedPath }
                    .thenBy { it.id },
            )
    private var closed = false
    override val totalCount: Long get() = entries.size.toLong()

    override suspend fun page(
        offset: Long,
        limit: Int,
    ): List<VaultFolder> {
        check(!closed)
        require(offset >= 0 && limit in 1..256)
        return entries.drop(offset.coerceAtMost(entries.size.toLong()).toInt()).take(limit)
    }

    override fun close() {
        closed = true
    }
}

private class AndroidVaultRouteDirectorySnapshot(
    private val snapshot: VaultDirectorySnapshot,
) : VaultRouteDirectorySnapshot {
    override val totalCount get() = snapshot.totalCount

    override suspend fun page(
        offset: Long,
        limit: Int,
    ) = snapshot.page(offset, limit)

    override fun close() = snapshot.close()
}

const val VAULT_DIRECTORY_PAGE_SIZE = 128

interface VaultRouteSession {
    fun boundaryEndpoint(location: VaultLocation): BoundaryEndpoint = unsupportedVaultMutation()

    fun observePendingOffline(): kotlinx.coroutines.flow.Flow<Unit> = kotlinx.coroutines.flow.emptyFlow()

    suspend fun completePendingOffline() = Unit

    fun offlineAvailable(entry: VaultFolder): Boolean? = if (isOffline) true else null

    val isOffline: Boolean get() = false

    suspend fun pinOffline(entry: VaultFolder): Unit = unsupportedVaultMutation()

    suspend fun pinOfflineDirectory(path: String): Unit = unsupportedVaultMutation()

    val identity: VaultIdentity

    suspend fun list(path: String): List<VaultFolder>

    suspend fun openDirectory(
        path: String,
        showHidden: Boolean = false,
        excludedPath: String? = null,
    ): VaultRouteDirectorySnapshot = SmallVaultRouteDirectorySnapshot(list(path), showHidden, excludedPath)

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

    suspend fun queueUpload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): Unit = unsupportedVaultMutation()

    suspend fun replaceText(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun queueReplacement(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ): Unit = unsupportedVaultMutation()

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
    private val application: Application,
) : VaultRouteRepository {
    private val repository = VaultRepository(application)
    private val offline = VaultOfflineStore(application)
    private val accounts =
        eu.opencloud.android.next.core.database.FileBrowserStore(
            eu.opencloud.android.next.core.database.FileBrowserDatabase
                .create(application),
        )

    override suspend fun unlockAccountSnapshot(accountId: String): Any? =
        accounts.account(accountId)?.takeIf {
            it.isActive
        }

    override suspend fun rememberBinding(accountId: String): VaultRememberBinding? {
        val groups = accounts.vaultOfflineGroups()
        val activeBeforeCapture = accounts.account(accountId)?.isActive == true
        val owner = if (activeBeforeCapture) groups.captureOwner(accountId) else null
        val ownerMatchesAccount = owner?.accountId == accountId
        val ownerCurrentAfterCapture = owner != null && ownerMatchesAccount && groups.isCurrentOwner(owner)
        val activeAfterCapture = accounts.account(accountId)?.isActive == true
        val ownerCurrentAfterAccountCheck = owner != null && groups.isCurrentOwner(owner)
        val currentOwner =
            owner?.takeIf {
                ownerCurrentAfterCapture && activeAfterCapture && ownerCurrentAfterAccountCheck
            }
        return currentOwner?.let { VaultRememberBinding(it.incarnation, it.accountIdentityDigest) }
    }

    override fun unlockCredentialPermit(accountId: String): () -> Boolean =
        eu.opencloud.android.next.core.security.AccountSessions
            .get(application)
            .beginLease(accountId)

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
            AndroidOfflineVaultRouteSession(
                requireNotNull(offline.openWithPassword(accountId, target, password)),
                application,
                offline,
            )
        } else {
            AndroidVaultRouteSession(repository.unlock(accountId, target, vaultPath, password), offline, application)
        }

    override suspend fun unlockWithKeyMaterial(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        keyMaterial: ByteArray,
    ): VaultRouteSession =
        if (target.offlineOnly) {
            AndroidOfflineVaultRouteSession(
                requireNotNull(offline.openWithKeyMaterial(accountId, target, keyMaterial)),
                application,
                offline,
            )
        } else {
            AndroidVaultRouteSession(
                repository.unlockWithKeyMaterial(accountId, target, vaultPath, keyMaterial),
                offline,
                application,
            )
        }
}

private class AndroidVaultRouteSession(
    private val session: VaultSession,
    private val offline: VaultOfflineStore,
    private val application: Application,
) : VaultRouteSession {
    override fun boundaryEndpoint(location: VaultLocation): BoundaryEndpoint = VaultBoundaryEndpoint(session, location)

    override suspend fun pinOffline(entry: VaultFolder) {
        if (entry.isFolder) {
            session.enqueueBackgroundOfflineGroup(application, entry.path, entry)
        } else {
            session.enqueueBackgroundOfflineDownload(application, entry)
        }
    }

    override fun observePendingOffline(): kotlinx.coroutines.flow.Flow<Unit> =
        pendingOfflineDownloads(application, identity)

    override suspend fun completePendingOffline() {
        session.completePendingOfflineGroups(application, offline)
        session.completePendingOfflineDownloads(application, offline)
        val revision = offlineListingRevision
        refreshPageOfflineStatus(lastPageEntries, revision)
    }

    override suspend fun pinOfflineDirectory(path: String) {
        session.enqueueBackgroundOfflineGroup(application, path)
    }

    override val identity get() = session.identity

    private var savedFiles: List<VaultFolder>? = null
    private var lastPageEntries: List<VaultFolder> = emptyList()
    private var offlineListingRevision = 0L

    override fun offlineAvailable(entry: VaultFolder): Boolean? =
        if (entry.isFolder) {
            null
        } else {
            savedFiles?.any {
                it.encryptedPath == entry.encryptedPath && it.strongETag == entry.strongETag
            }
        }

    override suspend fun list(path: String): List<VaultFolder> {
        ++offlineListingRevision
        lastPageEntries = emptyList()
        savedFiles = null
        return session.list(path)
    }

    override suspend fun openDirectory(
        path: String,
        showHidden: Boolean,
        excludedPath: String?,
    ): VaultRouteDirectorySnapshot {
        val snapshot = session.openDirectory(path, showHidden, excludedPath)
        val revision = ++offlineListingRevision
        return object : VaultRouteDirectorySnapshot {
            override val totalCount get() = snapshot.totalCount

            override suspend fun page(
                offset: Long,
                limit: Int,
            ): List<VaultFolder> {
                var delivered = false
                try {
                    val entries = snapshot.page(offset, limit)
                    lastPageEntries = entries
                    refreshPageOfflineStatus(entries, revision)
                    currentCoroutineContext().ensureActive()
                    delivered = true
                    return entries
                } finally {
                    if (!delivered) snapshot.close()
                }
            }

            override fun close() {
                if (offlineListingRevision == revision) {
                    offlineListingRevision++
                    lastPageEntries = emptyList()
                    savedFiles = null
                }
                snapshot.close()
            }
        }
    }

    @Suppress("TooGenericExceptionCaught") // Optional status cannot block live encrypted browsing.
    private suspend fun refreshPageOfflineStatus(entries: List<VaultFolder>, revision: Long) {
        val refreshed =
            try {
                session.offlineFiles(offline, entries)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null
            }
        if (revision == offlineListingRevision) savedFiles = refreshed
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

    override suspend fun queueUpload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ) {
        session.enqueueBackgroundUpload(application, parentPath, name, source, size)
    }

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

    override suspend fun queueReplacement(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ) {
        session.enqueueBackgroundReplacement(application, entry, source, size)
    }

    override suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long,
    ) = session.download(entry, sink, maxPlaintextBytes)

    override suspend fun renameVaultRoot(newName: String) = session.renameVaultRoot(newName)

    override suspend fun deleteVaultRoot() = session.deleteVaultRoot()

    override fun close() {
        savedFiles = null
        lastPageEntries = emptyList()
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

private class VaultRememberCommitUnknownException(
    val safelyCleared: Boolean,
) : IllegalStateException("Device remember enrollment outcome was unknown.")

private class VaultRememberRevocationException : IllegalStateException("The previous phone key could not be revoked.")

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
    private val application: Application,
    private val offline: VaultOfflineStore,
) : VaultRouteSession {
    override val isOffline = true
    override val identity get() = session.identity

    override fun observePendingOffline(): kotlinx.coroutines.flow.Flow<Unit> =
        pendingOfflineDownloads(application, identity)

    override suspend fun completePendingOffline() {
        session.completePendingOfflineGroups(application, offline)
        session.completePendingOfflineDownloads(application, offline)
    }

    override suspend fun list(path: String) = session.list(path)

    override suspend fun openDirectory(
        path: String,
        showHidden: Boolean,
        excludedPath: String?,
    ): VaultRouteDirectorySnapshot =
        AndroidVaultRouteDirectorySnapshot(session.openDirectory(path, showHidden, excludedPath))

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

private fun isVaultVideo(name: String): Boolean =
    name.substringAfterLast('.', "").lowercase(java.util.Locale.ROOT) in
        setOf("mp4", "m4v", "mov", "webm", "mkv", "3gp", "avi", "mpeg", "mpg")

private fun pendingOfflineDownloads(
    application: Application,
    identity: VaultIdentity,
): kotlinx.coroutines.flow.Flow<Unit> {
    val store =
        eu.opencloud.android.next.core.database.FileBrowserStore(
            eu.opencloud.android.next.core.database.FileBrowserDatabase
                .create(application),
        )
    return kotlinx.coroutines.flow
        .combine(
            store.observeAwaitingCiphertextDownloads(identity.accountId, "vault-offline:${identity.remoteVaultId}"),
            store.vaultOfflineGroups().observeAwaiting(identity.accountId, identity.driveId, identity.remoteVaultId),
        ) { files, group ->
            listOfNotNull(files, group).joinToString("|").takeIf { it.isNotEmpty() }
        }.pendingOfflineCompletionEvents()
}

/** An empty queue separates attempts, even when a retry retains the same transfer identity. */
internal fun Flow<String?>.pendingOfflineCompletionEvents(): Flow<Unit> =
    distinctUntilChanged()
        .filterNotNull()
        .map { Unit }
