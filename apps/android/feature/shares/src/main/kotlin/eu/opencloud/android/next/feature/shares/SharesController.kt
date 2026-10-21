package eu.opencloud.android.next.feature.shares

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.ShareEntity
import eu.opencloud.android.next.core.network.CreateShareRequest
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalDate

/** UI calls and state publication run on the owner's (main) dispatcher. */
internal class SharesController(
    private val owner: CoroutineScope,
    private val backend: SharesBackend,
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val errorMessage: (OpenCloudError) -> String = { it.safeMessage() },
) {
    private val mutableState = MutableStateFlow(SharesUiState())
    val state = mutableState.asStateFlow()
    private var accountId: String? = null
    private var session = SupervisorJob(owner.coroutineContext[Job])
    private var scope = CoroutineScope(owner.coroutineContext + session)
    private var resourceJob: Job? = null
    private var searchJob: Job? = null
    private var refreshJob: Job? = null
    private var pendingOperations = 0

    fun load(
        accountId: String,
        resource: ResourceEntity? = null,
    ) {
        require(resource == null || resource.accountId == accountId)
        if (this.accountId == accountId && mutableState.value.resource == resource) return
        session.cancel()
        session = SupervisorJob(owner.coroutineContext[Job])
        scope = CoroutineScope(owner.coroutineContext + session)
        this.accountId = accountId
        pendingOperations = 0
        mutableState.value = SharesUiState(category = state.value.category, resource = resource)
        scope.launch {
            reportingFailure("Could not load shares") {
                val account = withContext(io) { backend.account(accountId) }
                currentCoroutineContext().ensureActive()
                mutableState.value = state.value.copy(account = account)
                backend.observe(accountId).collect { values ->
                    currentCoroutineContext().ensureActive()
                    mutableState.value = state.value.copy(shares = values)
                }
            }
        }
        refresh()
        resource?.let(::loadResource)
    }

    fun selectCategory(value: ShareCategory) {
        mutableState.value = state.value.copy(category = value)
    }

    fun refresh() {
        val id = accountId ?: return
        refreshJob?.cancel()
        refreshJob = launchOperation(failureLabel = "Could not refresh shares") { backend.refresh(id) }
    }

    fun loadResource(resource: ResourceEntity) {
        if (resource.accountId != accountId) return
        if (state.value.resource != resource) {
            load(resource.accountId, resource)
            return
        }
        resourceJob?.cancel()
        searchJob?.cancel()
        mutableState.value =
            state.value.copy(resource = resource, resourceShares = emptyList(), recipients = emptyList())
        resourceJob =
            scope.launch {
                mutableState.value = state.value.copy(loading = true)
                try {
                    reportingFailure("Could not refresh this file's shares") {
                        val shares = withContext(io) { backend.resourceShares(resource) }
                        currentCoroutineContext().ensureActive()
                        mutableState.value = state.value.copy(resourceShares = shares)
                    }
                } finally {
                    if (currentCoroutineContext().isActive) {
                        mutableState.value = state.value.copy(loading = false)
                    }
                }
            }
    }

    fun searchRecipients(query: String) {
        val id = accountId ?: return
        searchJob?.cancel()
        mutableState.value = state.value.copy(recipients = emptyList())
        if (query.length < 2) return
        searchJob =
            scope.launch {
                reportingFailure("Could not find recipients") {
                    val recipients = withContext(io) { backend.recipients(id, query) }
                    currentCoroutineContext().ensureActive()
                    mutableState.value = state.value.copy(recipients = recipients)
                }
            }
    }

    fun createRecipientShare(
        recipient: ShareRecipient,
        permissions: Int,
    ) {
        val id = accountId ?: return
        val resource = state.value.resource ?: return
        launchOperation("Share created.", onSuccess = { showConfirmedShare(it.share, resource) }) {
            backend.create(
                id,
                CreateShareRequest(
                    resource.path,
                    recipient.type,
                    recipient.shareWith,
                    permissions,
                    resourceId = resource.remoteId,
                ),
            )
        }
    }

    fun createPublicLink(
        label: String,
        password: String?,
        expiration: LocalDate?,
        permissions: Int,
    ) {
        val id = accountId ?: return
        val resource = state.value.resource ?: return
        launchOperation(
            "Public link created.",
            failureLabel = "Could not create public link",
            onSuccess = {
                if (state.value.resource == resource) {
                    mutableState.value = state.value.copy(createdPublicLink = it.publicLink)
                    showConfirmedShare(it.share, resource)
                }
            },
        ) {
            backend.create(
                id,
                CreateShareRequest(
                    resource.path,
                    OcsShareType.PUBLIC_LINK,
                    permissions = permissions,
                    label = label,
                    password = password,
                    expirationDate = expiration,
                    resourceId = resource.remoteId,
                ),
            )
        }
    }

    fun updatePermissions(
        share: ShareEntity,
        permissions: Int,
    ) {
        val id = accountId ?: return
        if (share.accountId != id) return
        launchOperation("Permissions updated.") { backend.update(id, share.remoteId, permissions) }
    }

    fun revoke(share: ShareEntity) {
        val id = accountId ?: return
        if (share.accountId != id) return
        launchOperation("Share revoked.", onSuccess = { state.value.resource?.let(::loadResource) }) {
            backend.revoke(id, share.remoteId)
        }
    }

    fun dismissNotice() {
        mutableState.value = state.value.copy(error = null, message = null, createdPublicLink = null)
    }

    private fun <T> launchOperation(
        message: String? = null,
        failureLabel: String = "Sharing request failed",
        onSuccess: (T) -> Unit = {},
        action: suspend () -> T,
    ): Job =
        scope.launch {
            val operationSession = session
            pendingOperations++
            mutableState.value = state.value.copy(saving = true, error = null)
            try {
                reportingFailure(failureLabel) {
                    val result = withContext(io) { action() }
                    currentCoroutineContext().ensureActive()
                    onSuccess(result)
                    mutableState.value = state.value.copy(message = message)
                }
            } finally {
                if (session === operationSession) {
                    pendingOperations--
                    mutableState.value = state.value.copy(saving = pendingOperations > 0)
                }
            }
        }

    private fun showConfirmedShare(
        share: ShareEntity,
        resource: ResourceEntity,
    ) {
        if (state.value.resource == resource) {
            mutableState.value =
                state.value.copy(
                    resourceShares = state.value.resourceShares.filterNot { it.remoteId == share.remoteId } + share,
                )
        }
    }

    // This UI boundary maps backend failures to safe notices; cancellation always propagates.
    @Suppress("TooGenericExceptionCaught")
    private suspend fun reportingFailure(
        label: String,
        action: suspend () -> Unit,
    ) {
        try {
            action()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (error: Exception) {
            currentCoroutineContext().ensureActive()
            mutableState.value = state.value.copy(error = "$label: ${errorMessage(error.toOpenCloudError())}")
        }
    }
}
