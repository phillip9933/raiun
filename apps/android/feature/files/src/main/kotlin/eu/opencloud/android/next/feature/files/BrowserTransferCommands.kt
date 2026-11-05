package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.sync.TransferManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Conflict decisions retain their captured account; completion only updates that account epoch's UI. */
@Suppress("LongParameterList")
internal class BrowserTransferCommands(
    private val scope: CoroutineScope,
    private val accountContext: BrowserAccountContext,
    private val state: StateFlow<FileBrowserUiState>,
    private val backend: BrowserTransferBackend,
    private val reduce: (FileBrowserUiState.() -> FileBrowserUiState) -> Unit,
    private val failureMessage: (Throwable) -> String,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    fun resolveConflict(
        transfer: TransferEntity,
        decision: ConflictDecision,
    ) {
        val binding = accountContext.binding ?: return
        if (transfer.accountId != binding.accountId || state.value.bulkConflictCancelling) return
        scope.launch {
            runCatching {
                withContext(ioDispatcher) {
                    when (decision) {
                        ConflictDecision.REPLACE -> backend.retryConflict(transfer, overwrite = true, keepBoth = false)
                        ConflictDecision.KEEP_BOTH ->
                            backend.retryConflict(
                                transfer,
                                overwrite = false,
                                keepBoth = true,
                            )
                        ConflictDecision.CANCEL -> backend.cancelConflict(transfer)
                    }
                }
            }.onFailure { publish(binding) { copy(error = failureMessage(it)) } }
        }
    }

    fun cancelUploadConflicts() {
        val binding = accountContext.binding
        if (binding == null || binding.accountId.isBlank()) return
        val account = binding.accountId
        val hasConflicts =
            state.value.transfers.any {
                it.accountId == account &&
                    it.direction == TransferDirection.UPLOAD.name &&
                    it.state == TransferState.CONFLICT.name
            }
        if (state.value.bulkConflictCancelling || !hasConflicts) return
        reduce { copy(bulkConflictCancelling = true, error = null) }
        scope.launch {
            runCatching { withContext(ioDispatcher) { backend.cancelUploadConflicts(account) } }
                .onFailure { failure ->
                    publish(binding) { copy(bulkConflictCancelling = false, error = failureMessage(failure)) }
                }.onSuccess { publish(binding) { copy(bulkConflictCancelling = false) } }
        }
    }

    private suspend fun publish(
        binding: BrowserAccountBinding,
        transform: FileBrowserUiState.() -> FileBrowserUiState,
    ) = accountContext.publishAccount(binding) { reduce(transform) }
}

internal interface BrowserTransferBackend {
    suspend fun retryConflict(
        transfer: TransferEntity,
        overwrite: Boolean,
        keepBoth: Boolean,
    )

    suspend fun cancelConflict(transfer: TransferEntity)

    suspend fun cancelUploadConflicts(accountId: String)
}

internal class AndroidBrowserTransferBackend(
    private val transfers: TransferManager,
) : BrowserTransferBackend {
    override suspend fun retryConflict(
        transfer: TransferEntity,
        overwrite: Boolean,
        keepBoth: Boolean,
    ) = transfers.retryConflict(transfer, overwrite, keepBoth)

    override suspend fun cancelConflict(transfer: TransferEntity) = transfers.cancelConflict(transfer)

    override suspend fun cancelUploadConflicts(accountId: String) {
        transfers.cancelUploadConflicts(accountId)
    }
}
