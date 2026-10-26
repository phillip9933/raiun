package eu.opencloud.android.next.feature.transfers

import android.app.Application
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CloudDownload
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Restore
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.TransferManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
@Suppress("FunctionNaming", "ktlint:standard:function-naming")
fun TransfersRoute(
    accountId: String,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    onOpenFileActions: (() -> Unit)? = null,
    viewModel: TransfersViewModel = viewModel(key = "transfers-$accountId"),
) {
    val state by viewModel.state.collectAsState()
    var showEdits by remember { mutableStateOf(false) }
    LaunchedEffect(accountId) { viewModel.load(accountId) }
    TransfersScreen(
        state = state,
        selectedAccountId = accountId,
        onNavigateBack = onNavigateBack,
        onRetry = viewModel::retry,
        onCancel = viewModel::cancel,
        onResolveConflict = viewModel::resolveConflict,
        onRetryAll = viewModel::retryAll,
        onClearAll = viewModel::clearAll,
        onCancelUploadConflicts = viewModel::cancelUploadConflicts,
        onDismissError = viewModel::dismissError,
        modifier = modifier,
        onOpenFileActions = onOpenFileActions,
        onReviewEdits = { showEdits = true },
    )
    if (showEdits) DocumentEditsDialog(accountId, onDismiss = { showEdits = false })
}

class TransfersViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val manager = TransferManager(application, store)
    private val mutableState = MutableStateFlow(TransfersUiState())
    val state: StateFlow<TransfersUiState> = mutableState.asStateFlow()
    private var loadedAccountId: String? = null

    fun load(accountId: String) {
        if (loadedAccountId == accountId) return
        loadedAccountId = accountId
        mutableState.update {
            it.copy(
                active = emptyList(),
                failed = emptyList(),
                history = emptyList(),
                bulkConflictCancelling = false,
            )
        }
        viewModelScope.launch(Dispatchers.IO) {
            kotlinx.coroutines.flow
                .combine(
                    store.observeTransfers(accountId),
                    store.observeSpaces(accountId),
                ) { transfers, spaces ->
                    categorizeTransfers(transfers).copy(spaceNames = spaces.associate { it.driveId to it.name })
                }.collectLatest { snapshot ->
                    if (loadedAccountId != accountId) return@collectLatest
                    mutableState.update { current ->
                        current.copy(
                            spaceNames = snapshot.spaceNames,
                            active = snapshot.active,
                            failed = snapshot.failed,
                            history = snapshot.history,
                        )
                    }
                }
        }
    }

    fun retry(transfer: TransferEntity) = runAction { manager.retry(transfer) }

    fun cancel(transfer: TransferEntity) = runAction { manager.cancel(transfer) }

    fun resolveConflict(
        transfer: TransferEntity,
        decision: TransferConflictDecision,
    ) = runAction {
        when (decision) {
            TransferConflictDecision.REPLACE -> manager.retryConflict(transfer, overwrite = true)
            TransferConflictDecision.KEEP_BOTH -> manager.retryConflict(transfer, overwrite = false, keepBoth = true)
            TransferConflictDecision.CANCEL -> manager.cancelConflict(transfer)
        }
    }

    fun clearHistory() {
        val accountId = loadedAccountId ?: return
        runAction { manager.clearHistory(accountId) }
    }

    fun retryAll() {
        val accountId = loadedAccountId ?: return
        if (state.value.bulkRetrying ||
            bulkUploadRetryTargets(state.value.active + state.value.failed).isEmpty()
        ) {
            return
        }
        mutableState.value = mutableState.value.copy(bulkRetrying = true, bulkRetryFeedback = null, error = null)
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { manager.retryFailedUploads(accountId) } }
                .onSuccess { result ->
                    val application = getApplication<Application>()
                    mutableState.value =
                        mutableState.value.copy(
                            bulkRetrying = false,
                            bulkRetryFeedback =
                                application.localizedString(
                                    R.string.transfers_bulk_retry_result,
                                    result.retried,
                                    result.needsAttention,
                                ),
                        )
                }.onFailure {
                    mutableState.value =
                        mutableState.value.copy(
                            bulkRetrying = false,
                            error =
                                it.message
                                    ?: getApplication<Application>().localizedString(R.string.transfers_action_failed),
                        )
                }
        }
    }

    fun clearAll() {
        val accountId = loadedAccountId ?: return
        val transfers = state.value.active + state.value.failed + state.value.history
        runAction { manager.clearAll(accountId, transfers) }
    }

    fun cancelUploadConflicts() {
        val accountId = loadedAccountId?.takeIf(String::isNotBlank) ?: return
        if (state.value.bulkConflictCancelling ||
            bulkUploadConflictTargets(state.value.failed, accountId).isEmpty()
        ) {
            return
        }
        mutableState.update { it.copy(bulkConflictCancelling = true, error = null) }
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { manager.cancelUploadConflicts(accountId) } }
                .onFailure {
                    if (loadedAccountId == accountId) {
                        mutableState.update {
                            it.copy(
                                bulkConflictCancelling = false,
                                error = getApplication<Application>().localizedString(R.string.transfers_action_failed),
                            )
                        }
                    }
                }.onSuccess {
                    if (loadedAccountId == accountId) {
                        mutableState.update { it.copy(bulkConflictCancelling = false) }
                    }
                }
        }
    }

    fun dismissError() {
        mutableState.value = mutableState.value.copy(error = null, bulkRetryFeedback = null)
    }

    private fun runAction(action: suspend () -> Unit) {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { action() } }
                .onFailure {
                    mutableState.value =
                        mutableState.value.copy(
                            error =
                                it.message
                                    ?: getApplication<Application>().localizedString(R.string.transfers_action_failed),
                        )
                }
        }
    }
}

data class TransfersUiState(
    val spaceNames: Map<String, String> = emptyMap(),
    val active: List<TransferEntity> = emptyList(),
    val failed: List<TransferEntity> = emptyList(),
    val history: List<TransferEntity> = emptyList(),
    val error: String? = null,
    val bulkRetryFeedback: String? = null,
    val bulkRetrying: Boolean = false,
    val bulkConflictCancelling: Boolean = false,
)

enum class TransferConflictDecision { REPLACE, KEEP_BOTH, CANCEL }

internal fun categorizeTransfers(transfers: List<TransferEntity>): TransfersUiState =
    TransfersUiState(
        active = transfers.filter { it.state in ACTIVE_STATES },
        failed = transfers.filter { it.state in FAILED_STATES },
        history = transfers.filter { it.state in HISTORY_STATES },
    )

internal fun bulkUploadRetryTargets(transfers: List<TransferEntity>): List<TransferEntity> =
    transfers.filter {
        it.direction == TransferDirection.UPLOAD.name &&
            it.state in setOf(TransferState.FAILED.name, TransferState.RETRY.name)
    }

internal fun bulkUploadConflictTargets(
    transfers: List<TransferEntity>,
    accountId: String,
): List<TransferEntity> =
    transfers.filter {
        it.accountId == accountId &&
            it.direction == TransferDirection.UPLOAD.name &&
            it.state == TransferState.CONFLICT.name
    }

private val ACTIVE_STATES =
    setOf(TransferState.QUEUED.name, TransferState.RUNNING.name, TransferState.RETRY.name, "AWAITING_UNLOCK")
private val FAILED_STATES = setOf(TransferState.FAILED.name, TransferState.CONFLICT.name)
private val HISTORY_STATES = setOf(TransferState.SUCCEEDED.name, TransferState.CANCELLED.name)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("FunctionNaming", "ktlint:standard:function-naming", "LongParameterList")
fun TransfersScreen(
    state: TransfersUiState,
    onNavigateBack: () -> Unit,
    onRetry: (TransferEntity) -> Unit,
    onCancel: (TransferEntity) -> Unit,
    onResolveConflict: (TransferEntity, TransferConflictDecision) -> Unit,
    onRetryAll: () -> Unit,
    onClearAll: () -> Unit,
    onDismissError: () -> Unit,
    modifier: Modifier = Modifier,
    onCancelUploadConflicts: () -> Unit = {},
    selectedAccountId: String? = null,
    onOpenFileActions: (() -> Unit)? = null,
    onReviewEdits: (() -> Unit)? = null,
) {
    var confirmClearAll by remember { mutableStateOf(false) }
    var confirmCancelConflicts by remember(selectedAccountId) { mutableStateOf(false) }
    var filters by rememberSaveable(stateSaver = transferFiltersSaver) { mutableStateOf(TransferFilters()) }
    val hasTransfers = state.active.isNotEmpty() || state.failed.isNotEmpty() || state.history.isNotEmpty()
    val conflictCount =
        state.failed.count {
            (selectedAccountId == null || it.accountId == selectedAccountId) &&
                it.direction == TransferDirection.UPLOAD.name &&
                it.state == TransferState.CONFLICT.name
        }
    Scaffold(
        modifier = modifier,
        floatingActionButton = {
            TransfersUploadButton(onOpenFileActions)
        },
        topBar = {
            TransfersTopBar(
                onNavigateBack,
                onReviewEdits,
                hasTransfers,
                onCancelUploadConflicts =
                    if (conflictCount > 0 && !state.bulkConflictCancelling) {
                        { confirmCancelConflicts = true }
                    } else {
                        null
                    },
                onClearAll = { confirmClearAll = true },
            )
        },
    ) { padding ->
        if (state.active.isEmpty() && state.failed.isEmpty() && state.history.isEmpty()) {
            TransferEmptyState(padding)
        } else {
            FilteredTransferContent(
                state,
                filters,
                onFiltersChange = { filters = it },
                onRetry,
                onCancel,
                { transfer, decision -> if (!state.bulkConflictCancelling) onResolveConflict(transfer, decision) },
                onRetryAll,
                state.bulkConflictCancelling,
                Modifier.fillMaxSize().padding(padding),
            )
        }
    }
    TransfersFeedbackDialogs(state, onDismissError)
    TransfersClearAllDialog(
        open = confirmClearAll,
        onDismiss = { confirmClearAll = false },
        onConfirm = {
            confirmClearAll = false
            onClearAll()
        },
    )
    if (confirmCancelConflicts && conflictCount > 0) {
        TransfersCancelConflictsDialog(
            conflictCount,
            state.bulkConflictCancelling,
            onDismiss = { confirmCancelConflicts = false },
            onConfirm = {
                confirmCancelConflicts = false
                onCancelUploadConflicts()
            },
        )
    }
}

@Composable
private fun TransfersUploadButton(onOpenFileActions: (() -> Unit)?) {
    onOpenFileActions?.let { openActions ->
        FloatingActionButton(onClick = openActions) {
            Icon(Icons.Default.Add, contentDescription = stringResource(R.string.transfers_upload_files))
        }
    }
}

@Composable
private fun TransfersFeedbackDialogs(
    state: TransfersUiState,
    onDismiss: () -> Unit,
) {
    state.error?.let { error ->
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.transfers_action_title)) },
            text = { Text(error) },
            confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.transfers_ok)) } },
        )
    }
    state.bulkRetryFeedback?.let { feedback ->
        AlertDialog(
            onDismissRequest = onDismiss,
            title = { Text(stringResource(R.string.transfers_bulk_retry_title)) },
            text = { Text(feedback) },
            confirmButton = { TextButton(onClick = onDismiss) { Text(stringResource(R.string.transfers_ok)) } },
        )
    }
}

@Composable
private fun TransfersCancelConflictsDialog(
    count: Int,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.transfers_cancel_conflicts_title)) },
        text = { Text(stringResource(R.string.transfers_cancel_conflicts_confirmation, count)) },
        confirmButton = {
            TextButton(enabled = !busy, onClick = onConfirm) {
                Text(stringResource(R.string.transfers_cancel_conflicts_action))
            }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) {
                Text(stringResource(R.string.transfers_cancel))
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TransfersTopBar(
    onNavigateBack: () -> Unit,
    onReviewEdits: (() -> Unit)?,
    hasTransfers: Boolean,
    onCancelUploadConflicts: (() -> Unit)?,
    onClearAll: () -> Unit,
) {
    var showActions by remember { mutableStateOf(false) }
    TopAppBar(
        title = { Text(stringResource(R.string.transfers_screen_title)) },
        navigationIcon = {
            IconButton(onClick = onNavigateBack) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.transfers_back),
                )
            }
        },
        actions = {
            onReviewEdits?.let { review ->
                IconButton(onClick = review) {
                    Icon(
                        Icons.Default.Restore,
                        contentDescription = stringResource(R.string.transfers_recover_edits),
                    )
                }
            }
            if (hasTransfers) {
                Box {
                    IconButton(onClick = { showActions = true }) {
                        Icon(
                            Icons.Default.MoreVert,
                            contentDescription = stringResource(R.string.transfers_actions_description),
                        )
                    }
                    DropdownMenu(expanded = showActions, onDismissRequest = { showActions = false }) {
                        onCancelUploadConflicts?.let { cancelConflicts ->
                            DropdownMenuItem(
                                text = { Text(stringResource(R.string.transfers_cancel_conflicts_action)) },
                                leadingIcon = { Icon(Icons.Default.Cancel, contentDescription = null) },
                                onClick = {
                                    showActions = false
                                    cancelConflicts()
                                },
                            )
                        }
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.transfers_clear_all)) },
                            leadingIcon = { Icon(Icons.Default.Cancel, contentDescription = null) },
                            onClick = {
                                showActions = false
                                onClearAll()
                            },
                        )
                    }
                }
            }
        },
    )
}

@Composable
@Suppress("LongParameterList")
private fun FilteredTransferContent(
    state: TransfersUiState,
    filters: TransferFilters,
    onFiltersChange: (TransferFilters) -> Unit,
    onRetry: (TransferEntity) -> Unit,
    onCancel: (TransferEntity) -> Unit,
    onResolveConflict: (TransferEntity, TransferConflictDecision) -> Unit,
    onRetryAll: () -> Unit,
    conflictCancellationPending: Boolean,
    modifier: Modifier = Modifier,
) {
    val visibleState = state.filtered(filters, java.time.ZoneId.systemDefault())
    val hasBulkRetryTargets =
        filters == TransferFilters() && bulkUploadRetryTargets(state.active + state.failed).isNotEmpty()
    val activeQueuedTitle = stringResource(R.string.transfers_active_queued)
    val needsAttentionTitle = stringResource(R.string.transfers_needs_attention)
    val historyTitle = stringResource(R.string.transfers_history)
    Column(modifier) {
        TransferFilterControls(filters, onChange = onFiltersChange)
        LazyColumn(modifier = Modifier.weight(1f)) {
            if (visibleState.active.isEmpty() &&
                visibleState.failed.isEmpty() &&
                visibleState.history.isEmpty()
            ) {
                item(key = "filtered-empty") {
                    Column(Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingMd)) {
                        Text(
                            stringResource(R.string.transfers_filter_empty),
                            style = MaterialTheme.typography.titleMedium,
                        )
                        Text(stringResource(R.string.transfers_filter_empty_hint))
                    }
                }
            }
            transferSection(activeQueuedTitle, visibleState.active) { transfer ->
                TransferRow(
                    transfer,
                    onRetry =
                        if (transfer.state == TransferState.RETRY.name) ({ onRetry(transfer) }) else null,
                    onCancel = { onCancel(transfer) },
                    spaceName = state.spaceNames[transfer.spaceId],
                )
            }
            if (hasBulkRetryTargets) {
                item(key = "bulk-upload-retry") {
                    BulkUploadRetryButton(enabled = !state.bulkRetrying, onClick = onRetryAll)
                }
            }
            transferSection(needsAttentionTitle, visibleState.failed) { transfer ->
                FailedTransferRow(transfer, onRetry, onResolveConflict, conflictCancellationPending)
            }
            transferSection(historyTitle, visibleState.history) {
                TransferRow(it, spaceName = state.spaceNames[it.spaceId])
            }
        }
    }
}

@Composable
private fun TransfersClearAllDialog(
    open: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    if (!open) return
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.transfers_clear_all_title)) },
        text = { Text(stringResource(R.string.transfers_clear_all_confirmation)) },
        confirmButton = {
            TextButton(onClick = onConfirm) { Text(stringResource(R.string.transfers_clear_all)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.transfers_cancel)) }
        },
    )
}

private fun androidx.compose.foundation.lazy.LazyListScope.transferSection(
    title: String,
    transfers: List<TransferEntity>,
    row: @Composable (TransferEntity) -> Unit,
) {
    if (transfers.isEmpty()) return
    item {
        Text(
            title,
            modifier = Modifier.padding(OpenCloudDimensions.SpacingMd),
            style = MaterialTheme.typography.titleMedium,
        )
    }
    items(transfers, key = TransferEntity::id) { transfer -> row(transfer) }
}

@Composable
private fun FailedTransferRow(
    transfer: TransferEntity,
    onRetry: (TransferEntity) -> Unit,
    onResolveConflict: (TransferEntity, TransferConflictDecision) -> Unit,
    conflictCancellationPending: Boolean,
) {
    TransferRow(
        transfer = transfer,
        onRetry = if (transfer.state == TransferState.FAILED.name) ({ onRetry(transfer) }) else null,
        onConflict =
            if (transfer.state == TransferState.CONFLICT.name) {
                { decision -> onResolveConflict(transfer, decision) }
            } else {
                null
            },
        conflictActionsEnabled = !conflictCancellationPending,
    )
}

@Composable
private fun TransferEmptyState(padding: PaddingValues) {
    Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.CloudUpload, contentDescription = null)
            Text(stringResource(R.string.transfers_empty_title), style = MaterialTheme.typography.titleLarge)
            Text(stringResource(R.string.transfers_empty_description))
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
@Suppress("LongParameterList")
private fun TransferRow(
    transfer: TransferEntity,
    onRetry: (() -> Unit)? = null,
    onCancel: (() -> Unit)? = null,
    onConflict: ((TransferConflictDecision) -> Unit)? = null,
    conflictActionsEnabled: Boolean = true,
    spaceName: String? = null,
) {
    val progress =
        if (transfer.bytesTotal > 0) {
            (transfer.bytesTransferred.toFloat() / transfer.bytesTotal).coerceIn(0f, 1f)
        } else {
            0f
        }
    ListItem(
        headlineContent = { Text(transfer.displayName) },
        supportingContent = {
            Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
                Text(transferStatus(transfer))
                val location =
                    if (transfer.locationKind == "VAULT") {
                        stringResource(R.string.transfers_encrypted_destination)
                    } else {
                        listOfNotNull(spaceName, transfer.destinationPath).joinToString(" ")
                    }
                Text(
                    stringResource(
                        if (transfer.direction == TransferDirection.UPLOAD.name) {
                            R.string.transfers_destination_upload
                        } else {
                            R.string.transfers_destination_download
                        },
                        location,
                    ),
                )
                Text(
                    stringResource(R.string.transfers_started, transferDate(transfer.createdAtEpochMillis)),
                    style = MaterialTheme.typography.bodySmall,
                )
                if (transfer.updatedAtEpochMillis != transfer.createdAtEpochMillis) {
                    Text(
                        stringResource(
                            if (transfer.state == TransferState.SUCCEEDED.name) {
                                R.string.transfers_completed
                            } else {
                                R.string.transfers_updated
                            },
                            transferDate(transfer.updatedAtEpochMillis),
                        ),
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (transfer.state in ACTIVE_STATES &&
                    transfer.state != "AWAITING_UNLOCK"
                ) {
                    LinearProgressIndicator({ progress }, Modifier.fillMaxWidth())
                }
                transfer.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                TransferFailureDetails(transfer)
                onConflict?.let { TransferConflictActions(transfer.locationKind, conflictActionsEnabled, it) }
            }
        },
        leadingContent = {
            Icon(
                if (transfer.direction ==
                    TransferDirection.UPLOAD.name
                ) {
                    Icons.Default.CloudUpload
                } else {
                    Icons.Default.CloudDownload
                },
                contentDescription = null,
            )
        },
        trailingContent = {
            when {
                onRetry != null ->
                    IconButton(onClick = onRetry) {
                        Icon(Icons.Default.Refresh, contentDescription = stringResource(R.string.transfers_retry))
                    }
                onCancel != null ->
                    IconButton(onClick = onCancel) {
                        Icon(
                            Icons.Default.Cancel,
                            contentDescription = stringResource(R.string.transfers_cancel_transfer),
                        )
                    }
                transfer.state == TransferState.FAILED.name -> Icon(Icons.Default.Error, contentDescription = null)
            }
        },
    )
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun TransferConflictActions(
    locationKind: String,
    enabled: Boolean,
    onConflict: (TransferConflictDecision) -> Unit,
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
        if (locationKind !in setOf("SHARED_FOLDER", "VAULT")) {
            TextButton(onClick = { onConflict(TransferConflictDecision.REPLACE) }, enabled = enabled) {
                Text(stringResource(R.string.transfers_replace))
            }
        }
        if (locationKind != "VAULT") {
            TextButton(onClick = { onConflict(TransferConflictDecision.KEEP_BOTH) }, enabled = enabled) {
                Text(stringResource(R.string.transfers_keep_both))
            }
        }
        TextButton(onClick = { onConflict(TransferConflictDecision.CANCEL) }, enabled = enabled) {
            Text(stringResource(R.string.transfers_cancel))
        }
    }
}

@Composable
private fun TransferFailureDetails(transfer: TransferEntity) {
    var expanded by remember(transfer.id) { mutableStateOf(false) }
    if (transfer.state !in setOf("RETRY", "FAILED", "CONFLICT")) return
    val code = safeTransferDiagnosticCode(transfer.errorCode)
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
        if (transfer.state == "RETRY" && transfer.notBeforeEpochMillis > 0) {
            Text(
                stringResource(R.string.transfers_retry_after, transferDate(transfer.notBeforeEpochMillis)),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (code != null) {
            TextButton(onClick = { expanded = !expanded }) {
                Text(stringResource(if (expanded) R.string.transfers_hide_details else R.string.transfers_details))
            }
        }
        if (expanded && code != null) {
            TransferDiagnosticDetails(transfer, code)
        }
    }
}

@Composable
private fun TransferDiagnosticDetails(
    transfer: TransferEntity,
    code: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
        Text(
            stringResource(R.string.transfers_diagnostic_code, code, transfer.attemptCount),
            style = MaterialTheme.typography.bodySmall,
        )
        if (transfer.verificationPending) {
            Text(
                stringResource(R.string.transfers_verification_pending),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun transferStatus(transfer: TransferEntity): String {
    val status =
        if (transfer.state == "AWAITING_UNLOCK") {
            stringResource(R.string.transfers_awaiting_unlock)
        } else if (transfer.state == TransferState.RUNNING.name) {
            when {
                transfer.bytesTransferred == 0L -> stringResource(R.string.transfers_preparing)
                transfer.bytesTotal > 0 && transfer.bytesTransferred >= transfer.bytesTotal -> {
                    stringResource(R.string.transfers_verifying)
                }
                else -> stringResource(R.string.transfers_transferring)
            }
        } else {
            transferStateLabel(transfer.state)
        }
    return if (transfer.bytesTotal > 0) {
        stringResource(
            R.string.transfers_status_progress,
            status,
            transferSize(transfer.bytesTransferred),
            transferSize(transfer.bytesTotal),
        )
    } else {
        status
    }
}

@Composable
private fun transferStateLabel(state: String): String =
    when (TransferState.entries.firstOrNull { it.name == state }) {
        TransferState.QUEUED -> stringResource(R.string.transfers_status_queued)
        TransferState.RETRY -> stringResource(R.string.transfers_status_retry)
        TransferState.CONFLICT -> stringResource(R.string.transfers_status_conflict)
        TransferState.SUCCEEDED -> stringResource(R.string.transfers_status_succeeded)
        TransferState.FAILED -> stringResource(R.string.transfers_status_failed)
        TransferState.CANCELLED -> stringResource(R.string.transfers_status_cancelled)
        else -> state.lowercase().replaceFirstChar(Char::uppercase)
    }

@Composable
private fun transferSize(bytes: Long) =
    android.text.format.Formatter
        .formatShortFileSize(androidx.compose.ui.platform.LocalContext.current, bytes)

private fun transferDate(timestamp: Long) =
    java.text.DateFormat
        .getDateTimeInstance(
            java.text.DateFormat.MEDIUM,
            java.text.DateFormat.SHORT,
        ).format(java.util.Date(timestamp))

@Composable
private fun BulkUploadRetryButton(
    enabled: Boolean,
    onClick: () -> Unit,
) {
    OutlinedButton(
        onClick = onClick,
        enabled = enabled,
        modifier =
            Modifier.fillMaxWidth().padding(
                horizontal = OpenCloudDimensions.SpacingMd,
                vertical = OpenCloudDimensions.SpacingSm,
            ),
    ) {
        Text(stringResource(R.string.transfers_retry_all_failed))
    }
}
