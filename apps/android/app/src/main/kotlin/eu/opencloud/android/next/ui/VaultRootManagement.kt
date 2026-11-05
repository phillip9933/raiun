package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

internal interface VaultRootManagementPresentation {
    fun presentLocation(location: VaultLocation): VaultRouteLocation

    fun renamed(location: VaultLocation)

    fun showCatalog()

    fun reportFailure(
        failure: Exception,
        context: VaultFailureContext,
    )
}

/**
 * Root-management admission and execution. Lifecycle remains the sole mutable authority for
 * route/account, session/key, generation and operation cancellation; requests only borrow it.
 */
internal class VaultRootManagement(
    private val repository: VaultRouteRepository,
    private val scope: CoroutineScope,
    private val mutableState: MutableStateFlow<VaultRouteState>,
    private val lifecycle: VaultSessionLifecycle,
    private val presentation: VaultRootManagementPresentation,
) {
    /** A management lease is valid only for this unlocked root and route revision. */
    @Suppress("ReturnCount", "ComplexCondition") // Reject every stale lease dimension before exposing a target.
    fun managementTarget(expectedLockRevision: Long): VaultLocation? {
        val current = mutableState.value
        val selected = lifecycle.target ?: return null
        val opened = lifecycle.session ?: return null
        if (!lifecycle.routeActive ||
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

    fun managedSpaceChanged(
        location: VaultLocation,
        expectedLockRevision: Long,
    ) {
        if (!isManagementUnlocked(location, expectedLockRevision)) return
        lifecycle.updateTargetTitle(location.title)
        mutableState.value = mutableState.value.copy(selectedTitle = location.title)
    }

    @Suppress("TooGenericExceptionCaught") // Cleanup errors retain a locked route; cancellation is rethrown.
    fun managedSpaceLifecycleChanged(
        expectedLockRevision: Long,
        onComplete: () -> Unit,
    ) {
        val location = managementTarget(expectedLockRevision) ?: return
        val identity = lifecycle.session?.identity ?: return
        lifecycle.lock()
        val token = lifecycle.generation
        scope.launch {
            try {
                repository.removeOffline(identity)
                if (lifecycle.isCurrent(token, location.accountId)) onComplete()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                presentation.reportFailure(failure, VaultFailureContext(token, location.accountId))
            }
        }
    }

    @Suppress("ComplexCondition") // Only a live online root may expose server management.
    fun showRootActions() {
        if (lifecycle.session != null &&
            lifecycle.session?.isOffline == false &&
            mutableState.value.mode == VaultRouteMode.CONTENTS &&
            mutableState.value.currentPath.isEmpty()
        ) {
            mutableState.value = mutableState.value.copy(rootActionsVisible = true)
        }
    }

    fun dismissRootActions() {
        mutableState.value = mutableState.value.copy(rootActionsVisible = false)
    }

    fun renameRoot(
        name: String,
        expectedLockRevision: Long,
    ) {
        if (name.isBlank()) return
        val request = rootRequest(expectedLockRevision) ?: return
        lifecycle.trackOperation(scope.launch { renameRoot(request, name) })
    }

    @Suppress("TooGenericExceptionCaught") // Ambiguous server outcomes must relock the admitted session.
    private suspend fun renameRoot(
        request: RootMutationRequest,
        name: String,
    ) {
        try {
            val changed = request.opened.renameVaultRoot(name)
            // Invalidate the original offline identity even if this route has since been replaced.
            repository.removeOffline(request.identity)
            if (!isCurrent(request)) return
            lifecycle.closeSession()
            lifecycle.clearSensitiveState()
            lifecycle.replaceTarget(
                VaultSessionTarget(changed, changed.vaultPath, changed.title, changed.remoteVaultId),
            )
            presentation.renamed(changed)
            val identity = requireNotNull(lifecycle.currentTargetIdentity)
            val enrollment = lifecycle.enrollmentStatus(identity)
            lifecycle.updatePreferenceTitle(identity, changed.title)
            mutableState.value =
                VaultRouteState(
                    mode = VaultRouteMode.UNLOCK,
                    selectedLocation = presentation.presentLocation(changed),
                    selectedTitle = changed.title,
                    biometricEnrolled = enrollment.first,
                    biometricNeedsForget = enrollment.second,
                    lockRevision = mutableState.value.lockRevision + 1,
                )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            lockAfterAmbiguousRootChange(failure, request)
        }
    }

    fun deleteRoot(expectedLockRevision: Long) {
        val request = rootRequest(expectedLockRevision) ?: return
        lifecycle.trackOperation(scope.launch { deleteRoot(request) })
    }

    @Suppress("TooGenericExceptionCaught") // Ambiguous server outcomes must relock the admitted session.
    private suspend fun deleteRoot(request: RootMutationRequest) {
        try {
            request.opened.deleteVaultRoot()
            repository.removeOffline(request.identity)
            if (!isCurrent(request)) return
            lifecycle.closeSession()
            lifecycle.clearSensitiveState()
            lifecycle.clearTarget()
            presentation.showCatalog()
            lifecycle.cleanupDeletedTarget(request.identity)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            lockAfterAmbiguousRootChange(failure, request)
        }
    }

    @Suppress("ReturnCount") // Capture the existing online folder-root admission before consuming a generation.
    private fun rootRequest(expectedLockRevision: Long): RootMutationRequest? {
        if (!isCurrentRootAction(expectedLockRevision)) return null
        val opened = lifecycle.session ?: return null
        val account = lifecycle.accountId ?: return null
        val selected = lifecycle.target ?: return null
        if (selected.location.kind != VaultLocationKind.FOLDER_VAULT) return null
        val request = RootMutationRequest(opened, opened.identity, account, lifecycle.nextGeneration())
        mutableState.value = mutableState.value.copy(loading = true, rootActionsVisible = false, error = null)
        return request
    }

    private fun isCurrentRootAction(expectedLockRevision: Long): Boolean =
        lifecycle.routeActive &&
            !mutableState.value.loading &&
            mutableState.value.lockRevision == expectedLockRevision &&
            mutableState.value.mode == VaultRouteMode.CONTENTS &&
            mutableState.value.currentPath.isEmpty() &&
            mutableState.value.selectedLocation?.kind == VaultLocationKindUi.FOLDER_VAULT &&
            lifecycle.session?.isOffline == false &&
            lifecycle.target?.location?.kind == VaultLocationKind.FOLDER_VAULT

    private fun isCurrent(request: RootMutationRequest): Boolean =
        lifecycle.isCurrent(request.token, request.account) && lifecycle.session === request.opened

    private fun lockAfterAmbiguousRootChange(
        failure: Throwable,
        request: RootMutationRequest,
    ) {
        // Finalization can fail after this operation has itself closed the admitted session.
        // The same generation/account still owns that locked route, but never a replacement session.
        if (!lifecycle.isCurrent(request.token, request.account) ||
            lifecycle.session != null &&
            lifecycle.session !== request.opened
        ) {
            return
        }
        val classified = classifyVaultFailure(failure, VaultRouteError.OPERATION)
        lifecycle.closeSession()
        lifecycle.clearSensitiveState()
        val selected = lifecycle.target
        val enrollment = selected?.let { lifecycle.enrollmentStatus(it.expectedIdentity()) }
        mutableState.value =
            VaultRouteState(
                mode = if (selected == null) VaultRouteMode.CATALOG else VaultRouteMode.UNLOCK,
                selectedLocation = selected?.let { presentation.presentLocation(it.location) },
                selectedTitle = selected?.title,
                error = if (classified.requiresVaultRelock()) classified else VaultRouteError.OPERATION,
                biometricEnrolled = enrollment?.first ?: false,
                biometricNeedsForget = enrollment?.second ?: false,
                lockRevision = mutableState.value.lockRevision + 1,
            )
    }

    private data class RootMutationRequest(
        val opened: VaultRouteSession,
        val identity: VaultIdentity,
        val account: String,
        val token: Long,
    )
}
