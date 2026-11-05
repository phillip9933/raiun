package eu.opencloud.android.next.ui

import android.app.Application
import eu.opencloud.android.next.core.security.VaultDeviceRememberException
import eu.opencloud.android.next.core.security.VaultDeviceRememberOutcomeUnknownException
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.security.VaultRememberChoice
import eu.opencloud.android.next.core.security.VaultUnlockPolicy
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.crypto.Cipher

/** Presentation effects run on the route's main dispatcher; construction invokes no effects. */
internal interface VaultSessionPresentation {
    fun invalidateRoutePresentation()

    fun closeSessionContent()

    fun clearSensitivePresentation()

    fun clearPreview()

    fun presentLocation(location: VaultLocation): VaultRouteLocation

    fun presentEntries(entries: List<VaultFolder>): List<VaultRouteEntry>

    fun offersResolved()

    suspend fun postOpen(
        opened: VaultRouteSession,
        token: Long,
        account: String,
    )

    fun reportFailure(
        failure: Throwable,
        fallback: VaultRouteError,
        context: VaultFailureContext,
    )
}

/**
 * Sole route authority for account/generation admission, live sessions and unlock credentials.
 * Directory and preview workers borrow its admitted session; they never replace or retain its keys.
 */
@Suppress("LargeClass", "LongParameterList") // One route/key authority with explicitly injected services.
internal class VaultSessionLifecycle(
    private val application: Application,
    private val repository: VaultRouteRepository,
    private val biometricStore: VaultBiometricKeyStore,
    private val biometricPreferences: VaultOfferPreferences,
    private val ioDispatcher: CoroutineDispatcher,
    private val deviceRemember: VaultDeviceRememberAccess,
    private val scope: CoroutineScope,
    private val mutableState: MutableStateFlow<VaultRouteState>,
    private val directoryContent: VaultDirectoryContent,
    private val host: VaultSessionPresentation,
    private val unlockTiming: VaultUnlockTiming? = null,
) {
    var accountId: String? = null
        private set
    var routeActive = false
        private set
    var generation = 0L
        private set
    var session: VaultRouteSession? = null
        private set
    var target: VaultSessionTarget? = null
        private set
    var currentTargetIdentity: VaultIdentity? = null
        private set
    private var operationJob: Job? = null
    private var phoneSessionIssueIdentity: VaultIdentity? = null
    private var verifiedKeyMaterial: ByteArray? = null
    private var provenAccountSnapshot: Any? = null
    private var provenCredentialPermit: (() -> Boolean)? = null
    private var pendingBiometricIdentity: VaultIdentity? = null
    private var explicitDeviceForgetIdentity: VaultIdentity? = null
    private var explicitDeviceForgetJob: Job? = null
    private var pendingEnrollmentIdentity: VaultIdentity? = null
    private var pendingDeletedVaultCleanup: VaultIdentity? = null

    fun enter(account: String) {
        check(
            !routeActive && accountId == null && session == null,
        ) { "Leave the previous vault route before entering." }
        accountId = account
        routeActive = true
    }

    fun leave() {
        routeActive = false
        accountId = null
        invalidateRequests()
        clearSensitiveState()
        clearTarget()
    }

    fun selectTarget(selected: VaultSessionTarget) {
        requireCompatibleTarget(selected)
        target = selected
    }

    fun clearTarget() {
        target = null
        currentTargetIdentity = null
    }

    fun replaceTarget(selected: VaultSessionTarget) {
        requireCompatibleTarget(selected)
        target = selected
        currentTargetIdentity = selected.expectedIdentity()
    }

    private fun requireCompatibleTarget(selected: VaultSessionTarget) {
        check(routeActive && selected.location.accountId == accountId) {
            "The vault target must belong to the active route account."
        }
        check(session == null || session?.identity == selected.expectedIdentity()) {
            "Close the current vault session before replacing its target."
        }
    }

    fun updateTargetTitle(title: String) {
        val selected = target ?: return
        target = selected.copy(location = selected.location.copy(title = title), title = title)
        session?.identity?.let { updatePreferenceTitle(it, title) }
    }

    fun updatePreferenceTitle(
        identity: VaultIdentity,
        title: String,
    ) {
        runCatching {
            when (preferenceStatus(identity)) {
                VaultPreferenceStatus.REMEMBERED -> biometricPreferences.remember(identity, title, targetKind())
                VaultPreferenceStatus.DECLINED -> biometricPreferences.decline(identity, title, targetKind())
                null -> Unit
            }
        }
    }

    fun cleanupDeletedTarget(identity: VaultIdentity) {
        if (!clearDeletedVaultAccess(identity)) {
            pendingDeletedVaultCleanup = identity
            mutableState.value = mutableState.value.copy(error = VaultRouteError.BIOMETRIC_CLEANUP)
        }
    }

    fun trackOperation(job: Job) {
        operationJob = job
    }

    fun closeSession() {
        // Content snapshots and action leases must be invalidated before their backing session.
        host.closeSessionContent()
        session?.close()
        session = null
    }

    fun clearSensitiveState() {
        closeSession()
        host.clearSensitivePresentation()
        clearVerifiedKeyMaterial()
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
            scope.launch {
                var unlocked: VaultRouteSession? = null
                try {
                    val snapshot = repository.unlockAccountSnapshot(account)
                    val credentialPermit = repository.unlockCredentialPermit(account)
                    unlocked = repository.unlock(account, selected.location, selected.vaultPath, password)
                    if (!isCurrent(token, account)) {
                        unlocked.close()
                        return@launch
                    }
                    val installed =
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
                    if (installed) {
                        val adopted = unlocked
                        unlocked = null
                        host.postOpen(adopted, token, account)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    host.reportFailure(failure, VaultRouteError.UNLOCK, VaultFailureContext(token, account))
                } finally {
                    password.fill('\u0000')
                    unlocked?.close()
                }
            }
        unlockJob.invokeOnCompletion { password.fill('\u0000') }
        operationJob = unlockJob
    }

    // Admission can reject early; timing must rethrow the original cancellation/failure unchanged.
    @Suppress("ReturnCount", "TooGenericExceptionCaught", "ThrowsCount")
    private suspend fun installSession(
        opened: VaultRouteSession,
        selected: VaultSessionTarget,
        token: Long,
        account: String,
        phoneAdmission: PhoneUnlockAdmission = PhoneUnlockAdmission(),
        timing: VaultUnlockTiming? = null,
    ): Boolean {
        var finalAdmission: VaultUnlockSpan? = null
        var capturedMaterial: ByteArray? = null
        var firstDirectory: OpenedVaultDirectory? = null
        try {
            if (opened.identity != selected.expectedIdentity()) throw VaultIdentityChangedException()
            firstDirectory =
                timing.measure(VaultUnlockStage.INITIAL_DIRECTORY) { directoryContent.openFirst(opened, "") }
            finalAdmission = timing?.begin(VaultUnlockStage.FINAL_ADMISSION)
            if (!keepCurrentRouteSession(opened, token, account, phoneAdmission.reusedKey)) return false
            requireCurrentReuse(account, phoneAdmission)
            capturedMaterial = captureVerifiedMaterial(opened, phoneAdmission.captureKeyMaterial)
            if (capturedMaterial == null && phoneAdmission.provenBiometricMaterial != null) {
                capturedMaterial = phoneAdmission.provenBiometricMaterial.copyOf()
            }
            if (!keepCurrentRouteSession(opened, token, account, phoneAdmission.reusedKey)) return false
            val phoneSessionIssueCode = rememberProvenPhoneUnlock(opened, account, capturedMaterial, phoneAdmission)
            // Diagnosis crosses account/provider IO; an obsolete attempt cannot mutate a replacement route.
            if (!keepCurrentRouteSession(opened, token, account, phoneAdmission.reusedKey)) return false
            updatePhoneSessionIssue(opened.identity, phoneAdmission, phoneSessionIssueCode)
            val offers = determinePhoneUnlockOffers(opened, phoneAdmission, capturedMaterial)
            // Track the replacement snapshot locally until the final admission and synchronous adoption.
            firstDirectory = directoryContent.currentVisibility(opened, checkNotNull(firstDirectory))
            if (!keepCurrentRouteSession(opened, token, account, phoneAdmission.reusedKey)) return false
            publishOpenedSession(
                SessionPublication(
                    opened,
                    selected,
                    phoneAdmission,
                    checkNotNull(firstDirectory),
                    offers,
                ),
            )
            // No suspension is permitted between adoption and relinquishing these local owners.
            firstDirectory = null
            capturedMaterial = null
            finalAdmission?.finish(VaultUnlockOutcome.SUCCESS)
            return true
        } catch (cancelled: CancellationException) {
            finalAdmission?.finish(VaultUnlockOutcome.CANCELLED)
            throw cancelled
        } catch (failure: Throwable) {
            finalAdmission?.finish(VaultUnlockOutcome.FAILURE)
            throw failure
        } finally {
            finalAdmission?.finish(VaultUnlockOutcome.REJECTED)
            firstDirectory?.snapshot?.close()
            capturedMaterial?.fill(0)
        }
    }

    /** Final admission has completed; session, snapshot and key ownership transfer without suspension. */
    private fun publishOpenedSession(publication: SessionPublication) {
        val opened = publication.opened
        val selected = publication.selected
        val phoneAdmission = publication.phoneAdmission
        val offers = publication.offers
        val visibleDirectory = publication.initialDirectory
        val entries = visibleDirectory.entries
        closeSession()
        clearVerifiedKeyMaterial()
        session = opened
        directoryContent.adopt(visibleDirectory.snapshot)
        val page = VaultDirectoryPageState(0, visibleDirectory.snapshot.totalCount, entries.size, false)
        currentTargetIdentity = opened.identity
        verifiedKeyMaterial = offers.pendingMaterial
        provenAccountSnapshot = phoneAdmission.accountSnapshot
        provenCredentialPermit = phoneAdmission.credentialPermit
        mutableState.value =
            mutableState.value.copy(
                mode = VaultRouteMode.CONTENTS,
                offline = opened.isOffline,
                selectedLocation = host.presentLocation(selected.location),
                selectedTitle = selected.title,
                browseTitle = null,
                currentPath = "",
                entries = host.presentEntries(entries),
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
        host.offersResolved()
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
                runCatching { deviceRemember.choice(opened.identity) }.getOrNull() to
                    (
                        !VaultUnlockPolicy(application).askEveryTime() &&
                            runCatching { deviceRemember.isSupported() }.getOrDefault(false)
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
        val selected: VaultSessionTarget,
        val phoneAdmission: PhoneUnlockAdmission,
        val initialDirectory: OpenedVaultDirectory,
        val offers: PhoneUnlockOffers,
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
        // Reused-key admission cannot produce a biometric diagnosis; its guards remain above and around this call.
        if (admission.reusedKey != null) return null
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
                !VaultUnlockPolicy(application).askEveryTime() &&
                    runCatching { deviceRemember.isSupported() }.getOrDefault(false)
            }
        val remembered =
            withContext(
                ioDispatcher,
            ) { runCatching { deviceRemember.hasRemembered(identity) }.getOrDefault(false) }
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

    fun showPasswordUnlock(selected: VaultSessionTarget) {
        val token = nextGeneration()
        closeSession()
        clearVerifiedKeyMaterial()
        host.clearPreview()
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
                selectedLocation = host.presentLocation(selected.location),
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
    fun tryPhoneSessionUnlock(
        selected: VaultSessionTarget,
        token: Long,
    ) {
        val account = accountId ?: return
        // Keep the biometric prompt ineligible until this bounded lookup/revalidation finishes.
        mutableState.value = mutableState.value.copy(loading = true)
        operationJob =
            scope.launch {
                var key: VaultDeviceRememberKey? = null
                var opened: VaultRouteSession? = null
                var attemptedCachedKeyProof = false
                val total = unlockTiming?.begin(VaultUnlockStage.TOTAL)
                try {
                    val lookup =
                        unlockTiming.measure(VaultUnlockStage.LOCAL_RESTORE) {
                            resolvePhoneRestore(selected.expectedIdentity(), account, token)
                        }
                    if (lookup is PhoneRestoreLookup.RevocationFailed) {
                        showPhoneRestoreRevocationFailure(selected.expectedIdentity(), token, account)
                        return@launch
                    }
                    val ready = lookup as? PhoneRestoreLookup.Ready ?: return@launch
                    key = ready.key
                    if (!isCurrent(token, account)) return@launch
                    attemptedCachedKeyProof = true
                    opened =
                        unlockTiming.measure(VaultUnlockStage.SERVER_VERIFICATION) {
                            repository.unlockWithKeyMaterial(
                                account,
                                selected.location,
                                selected.vaultPath,
                                ready.key.material,
                            )
                        }
                    if (!isCurrent(token, account)) return@launch
                    val installed =
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
                            timing = unlockTiming,
                        )
                    if (installed) {
                        val adopted = opened
                        opened = null
                        total?.finish(VaultUnlockOutcome.SUCCESS)
                        host.postOpen(adopted, token, account)
                    }
                } catch (cancelled: CancellationException) {
                    total?.finish(VaultUnlockOutcome.CANCELLED)
                    throw cancelled
                } catch (_: Exception) {
                    total?.finish(VaultUnlockOutcome.FAILURE)
                    if (attemptedCachedKeyProof && isCurrent(token, account)) {
                        phoneSessionIssueIdentity = selected.expectedIdentity()
                        mutableState.value = mutableState.value.copy(phoneSessionIssueCode = "US7")
                    }
                } finally {
                    total?.finish(VaultUnlockOutcome.REJECTED)
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
                    runCatching { deviceRemember.hasRemembered(identity) }.getOrDefault(false)
                }
        val binding = if (remembered) withContext(ioDispatcher) { repository.rememberBinding(account) } else null
        val credentialPermit = if (binding != null) repository.unlockCredentialPermit(account) else null
        val restoredKey =
            if (binding != null && credentialPermit != null) {
                withContext(ioDispatcher) { deviceRemember.restore(identity, binding, credentialPermit) }
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
            !VaultUnlockPolicy(application).askEveryTime() &&
                runCatching { deviceRemember.isSupported() }.getOrDefault(false)
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
            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                val forgotten =
                    withContext(NonCancellable + ioDispatcher) {
                        previousForget?.join()
                        VaultDeviceRememberRevocations.awaitPredecessor(revocationTicket)
                        runCatching { deviceRemember.forget(identity) }.isSuccess.also {
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
                runCatching { deviceRemember.forget(identity) }.isSuccess.also {
                    VaultDeviceRememberRevocations.finish(ticket, it)
                }
            }
        return forgotten
    }

    /** Screen-off closes the live route while durable phone consent survives. */
    fun onDeviceLocked() {
        closeRouteSession()
    }

    fun closeRouteSession() {
        invalidateRequests()
        closeSession()
        clearSensitiveState()
        val currentTarget = target
        mutableState.value =
            mutableState.value.copy(
                mode = if (currentTarget != null) VaultRouteMode.UNLOCK else VaultRouteMode.CATALOG,
                selectedLocation = currentTarget?.let { host.presentLocation(it.location) },
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
            scope.launch {
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
                    val installed =
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
                    if (installed) {
                        val adopted = unlocked
                        unlocked = null
                        host.postOpen(adopted, token, account)
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    host.reportFailure(
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
            host.offersResolved()
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
        host.offersResolved()
    }

    /** Saves only after the user accepts the explicit per-location phone-remember question. */
    fun rememberOnPhone() {
        val request = capturePhoneRememberRequest() ?: return
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        operationJob =
            launchWithOwnedMaterial(scope, request.material) {
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
        val admission = withContext(ioDispatcher) { deviceRemember.begin(identity, binding) }
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
                deviceRemember.remember(admission, request.identity, binding, request.material, permit)
            } catch (_: VaultDeviceRememberOutcomeUnknownException) {
                val safelyCleared = runCatching { deviceRemember.forget(request.identity) }.isSuccess
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
        host.offersResolved()
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
            if (routeActive && session === request.opened && currentTargetIdentity == request.identity) {
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
            scope.launch {
                try {
                    withContext(ioDispatcher) { deviceRemember.decline(identity) }
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
                        host.offersResolved()
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
        selected: VaultSessionTarget?,
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

    fun enrollmentStatus(identity: VaultIdentity): Pair<Boolean, Boolean> =
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

    fun isCurrent(
        token: Long,
        account: String,
    ): Boolean = routeActive && accountId == account && generation == token

    fun nextGeneration(): Long {
        generation += 1
        operationJob?.cancel()
        operationJob = null
        pendingBiometricIdentity?.let { runCatching { biometricStore.cancelUnlock(it) } }
        pendingBiometricIdentity = null
        pendingEnrollmentIdentity?.let { runCatching { biometricStore.cancelEnrollment(it) } }
        pendingEnrollmentIdentity = null
        return generation
    }

    fun invalidateRequests() {
        generation += 1
        host.invalidateRoutePresentation()
        operationJob?.cancel()
        operationJob = null
        pendingBiometricIdentity?.let { runCatching { biometricStore.cancelUnlock(it) } }
        pendingBiometricIdentity = null
        pendingEnrollmentIdentity?.let { runCatching { biometricStore.cancelEnrollment(it) } }
        pendingEnrollmentIdentity = null
    }

    fun clearVerifiedKeyMaterial() {
        verifiedKeyMaterial?.fill(0)
        verifiedKeyMaterial = null
        provenAccountSnapshot = null
        provenCredentialPermit = null
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

    fun retryDeletedVaultCleanup(): Boolean {
        val identity = pendingDeletedVaultCleanup ?: return false
        if (clearDeletedVaultAccess(identity)) {
            pendingDeletedVaultCleanup = null
            mutableState.value = mutableState.value.copy(error = null)
        } else {
            mutableState.value = mutableState.value.copy(error = VaultRouteError.BIOMETRIC_CLEANUP)
        }
        return true
    }
}

internal data class VaultSessionTarget(
    val location: VaultLocation,
    val vaultPath: String,
    val title: String,
    val remoteVaultId: String,
) {
    fun expectedIdentity() =
        VaultIdentity(
            accountId = location.accountId,
            canonicalServer = location.canonicalServer,
            driveId = location.driveId,
            remoteVaultId = remoteVaultId,
        )
}

private class VaultRememberCommitUnknownException(
    val safelyCleared: Boolean,
) : IllegalStateException("Device remember enrollment outcome was unknown.")

private class VaultRememberRevocationException : IllegalStateException("The previous phone key could not be revoked.")
