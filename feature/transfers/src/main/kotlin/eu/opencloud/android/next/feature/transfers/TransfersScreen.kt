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
        onNavigateBack = onNavigateBack,
        onRetry = viewModel::retry,
        onCancel = viewModel::cancel,
        onResolveConflict = viewModel::resolveConflict,
        onRetryAll = viewModel::retryAll,
        onClearAll = viewModel::clearAll,
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
        viewModelScope.launch(Dispatchers.IO) {
            kotlinx.coroutines.flow
                .combine(
                    store.observeTransfers(accountId),
                    store.observeSpaces(accountId),
                ) { transfers, spaces ->
                    categorizeTransfers(transfers).copy(spaceNames = spaces.associate { it.driveId to it.name })
                }.collectLatest { snapshot ->
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

private val ACTIVE_STATES = setOf(TransferState.QUEUED.name, TransferState.RUNNING.name, TransferState.RETRY.name)
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
    onOpenFileActions: (() -> Unit)? = null,
    onReviewEdits: (() -> Unit)? = null,
) {
    var showActions by remember { mutableStateOf(false) }
    var confirmClearAll by remember { mutableStateOf(false) }
    val hasBulkRetryTargets = bulkUploadRetryTargets(state.active + state.failed).isNotEmpty()
    val hasTransfers = state.active.isNotEmpty() || state.failed.isNotEmpty() || state.history.isNotEmpty()
    val activeQueuedTitle = stringResource(R.string.transfers_active_queued)
    val needsAttentionTitle = stringResource(R.string.transfers_needs_attention)
    val historyTitle = stringResource(R.string.transfers_history)
    Scaffold(
        modifier = modifier,
        floatingActionButton = {
            onOpenFileActions?.let { openActions ->
                FloatingActionButton(onClick = openActions) {
                    Icon(Icons.Default.Add, contentDescription = stringResource(R.string.transfers_upload_files))
                }
            }
        },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.transfers_title)) },
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
                                DropdownMenuItem(
                                    text = { Text(stringResource(R.string.transfers_clear_all)) },
                                    leadingIcon = { Icon(Icons.Default.Cancel, contentDescription = null) },
                                    onClick = {
                                        showActions = false
                                        confirmClearAll = true
                                    },
                                )
                            }
                        }
                    }
                },
            )
        },
    ) { padding ->
        if (state.active.isEmpty() && state.failed.isEmpty() && state.history.isEmpty()) {
            TransferEmptyState(padding)
        } else {
            LazyColumn(
                contentPadding = padding,
                modifier = Modifier.fillMaxSize(),
            ) {
                transferSection(activeQueuedTitle, state.active) { transfer ->
                    TransferRow(
                        transfer,
                        onRetry = if (transfer.state == TransferState.RETRY.name) ({ onRetry(transfer) }) else null,
                        onCancel = { onCancel(transfer) },
                        spaceName = state.spaceNames[transfer.spaceId],
                    )
                }
                if (hasBulkRetryTargets) {
                    item(key = "bulk-upload-retry") {
                        BulkUploadRetryButton(enabled = !state.bulkRetrying, onClick = onRetryAll)
                    }
                }
                transferSection(needsAttentionTitle, state.failed) { transfer ->
                    FailedTransferRow(transfer, onRetry, onResolveConflict)
                }
                transferSection(historyTitle, state.history) {
                    TransferRow(it, spaceName = state.spaceNames[it.spaceId])
                }
            }
        }
    }
    state.error?.let { error ->
        AlertDialog(
            onDismissRequest = onDismissError,
            title = { Text(stringResource(R.string.transfers_action_title)) },
            text = { Text(error) },
            confirmButton = { TextButton(onClick = onDismissError) { Text(stringResource(R.string.transfers_ok)) } },
        )
    }
    state.bulkRetryFeedback?.let { feedback ->
        AlertDialog(
            onDismissRequest = onDismissError,
            title = { Text(stringResource(R.string.transfers_bulk_retry_title)) },
            text = { Text(feedback) },
            confirmButton = { TextButton(onClick = onDismissError) { Text(stringResource(R.string.transfers_ok)) } },
        )
    }
    if (confirmClearAll) {
        TransfersClearAllDialog(
            onDismiss = { confirmClearAll = false },
            onConfirm = {
                confirmClearAll = false
                onClearAll()
            },
        )
    }
}

@Composable
private fun TransfersClearAllDialog(
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
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
private fun TransferRow(
    transfer: TransferEntity,
    onRetry: (() -> Unit)? = null,
    onCancel: (() -> Unit)? = null,
    onConflict: ((TransferConflictDecision) -> Unit)? = null,
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
                val location = listOfNotNull(spaceName, transfer.destinationPath).joinToString(" ")
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
                if (transfer.state in ACTIVE_STATES) LinearProgressIndicator({ progress }, Modifier.fillMaxWidth())
                transfer.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (onConflict != null) {
                    FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
                        if (transfer.locationKind != "SHARED_FOLDER") {
                            TextButton(onClick = { onConflict(TransferConflictDecision.REPLACE) }) {
                                Text(stringResource(R.string.transfers_replace))
                            }
                        }
                        TextButton(onClick = { onConflict(TransferConflictDecision.KEEP_BOTH) }) {
                            Text(stringResource(R.string.transfers_keep_both))
                        }
                        TextButton(onClick = { onConflict(TransferConflictDecision.CANCEL) }) {
                            Text(stringResource(R.string.transfers_cancel))
                        }
                    }
                }
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

@Composable
private fun transferStatus(transfer: TransferEntity): String {
    val status =
        if (transfer.state == TransferState.RUNNING.name) {
            when {
                transfer.bytesTransferred == 0L -> stringResource(R.string.transfers_preparing)
                transfer.bytesTotal > 0 && transfer.bytesTransferred >= transfer.bytesTotal -> {
                    stringResource(R.string.transfers_verifying)
                }
                else -> stringResource(R.string.transfers_transferring)
            }
        } else {
            when (TransferState.entries.firstOrNull { it.name == transfer.state }) {
                TransferState.QUEUED -> stringResource(R.string.transfers_status_queued)
                TransferState.RETRY -> stringResource(R.string.transfers_status_retry)
                TransferState.CONFLICT -> stringResource(R.string.transfers_status_conflict)
                TransferState.SUCCEEDED -> stringResource(R.string.transfers_status_succeeded)
                TransferState.FAILED -> stringResource(R.string.transfers_status_failed)
                TransferState.CANCELLED -> stringResource(R.string.transfers_status_cancelled)
                TransferState.RUNNING, null -> transfer.state.lowercase().replaceFirstChar(Char::uppercase)
            }
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
