package eu.opencloud.android.next.feature.files

import android.app.Application
import android.net.Uri
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.sync.BackupScanDiagnostics
import eu.opencloud.android.next.core.sync.TransferManager
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.UUID

/** Backup command execution only; account admission, picker navigation and state reduction stay outside. */
@Suppress("LongParameterList")
internal class BrowserBackupCommands(
    private val scope: CoroutineScope,
    private val accountContext: BrowserAccountContext,
    private val state: StateFlow<FileBrowserUiState>,
    private val backend: BrowserBackupBackend,
    private val reduce: (FileBrowserUiState.() -> FileBrowserUiState) -> Unit,
    private val failureMessage: (Throwable) -> String,
    private val configuredMessage: () -> String,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    fun saveBackup(
        sourceTreeUri: Uri,
        draft: BackupDraft,
    ) {
        val binding = accountContext.binding ?: return
        val space = draft.spaceId ?: return
        scope.launch {
            // Creation historically reads provider metadata on the caller dispatcher before saving on IO.
            val backup =
                FolderBackupEntity(
                    id = UUID.randomUUID().toString(),
                    accountId = binding.accountId,
                    spaceId = space,
                    sourceTreeUri = sourceTreeUri.toString(),
                    sourceDisplayName = backend.sourceDirectoryName(sourceTreeUri),
                    destinationPath = draft.destinationPath.ifBlank { "/Camera Uploads" },
                    mediaType = draft.mediaType,
                    wifiOnly = draft.wifiOnly,
                    chargingOnly = draft.chargingOnly,
                    deleteAfterUpload = draft.deleteAfterUpload,
                    dateOrganization = draft.dateOrganization,
                    destinationKind = draft.destinationKind,
                    sharedShareId = draft.sharedShareId,
                    sharedFolderId = draft.sharedFolderId,
                    exclusionPatterns = draft.exclusionPatterns,
                    enabled = draft.enabled,
                )
            runCatching { withContext(ioDispatcher) { backend.saveBackup(backup) } }
                .onSuccess { publish(binding) { copy(message = configuredMessage()) } }
                .onFailure { publish(binding) { copy(error = failureMessage(it)) } }
        }
    }

    fun scanBackupsNow() = backend.scanBackupsNow()

    fun deleteBackup(id: String) {
        val backup = state.value.backups.firstOrNull { it.id == id }
        scope.launch(ioDispatcher) {
            backend.deleteBackup(id)
            backup?.let { backend.forgetDiagnostics(it) }
        }
    }

    fun completeBackupSourceSelection(
        expectedAccountId: String?,
        expectedBackupId: String?,
        expectedFingerprint: String?,
        draft: BackupDraft,
        selectedSource: Uri,
    ) {
        if (accountContext.binding?.accountId != expectedAccountId || expectedAccountId == null) return
        if (expectedBackupId == null) {
            saveBackup(selectedSource, draft)
        } else {
            val current =
                state.value.backups.firstOrNull {
                    it.id == expectedBackupId && it.accountId == expectedAccountId
                }
            if (current != null && backupSourceSelectionFingerprint(current) == expectedFingerprint) {
                updateBackup(current, draft, selectedSource)
            }
        }
    }

    fun updateBackup(
        backup: FolderBackupEntity,
        draft: BackupDraft,
        selectedSource: Uri? = null,
    ) {
        val binding = accountContext.binding ?: return
        if (backup.accountId != binding.accountId) return
        scope.launch {
            runCatching {
                withContext(ioDispatcher) {
                    backend.saveBackup(
                        backupSourceSelection(
                            backup,
                            selectedSource?.toString(),
                            selectedSource?.let(backend::sourceDirectoryName),
                        ).copy(
                            destinationPath = draft.destinationPath,
                            spaceId = draft.spaceId ?: backup.spaceId,
                            destinationKind = draft.destinationKind,
                            sharedShareId = draft.sharedShareId,
                            sharedFolderId = draft.sharedFolderId,
                            mediaType = draft.mediaType,
                            wifiOnly = draft.wifiOnly,
                            chargingOnly = draft.chargingOnly,
                            deleteAfterUpload = false,
                            lastSafeScanEpochMillis = 0,
                            dateOrganization = draft.dateOrganization,
                            exclusionPatterns = draft.exclusionPatterns,
                            enabled = draft.enabled,
                        ),
                    )
                }
            }.onFailure { publish(binding) { copy(error = failureMessage(it)) } }
        }
    }

    private suspend fun publish(
        binding: BrowserAccountBinding,
        transform: FileBrowserUiState.() -> FileBrowserUiState,
    ) = accountContext.publishAccount(binding) { reduce(transform) }
}

internal interface BrowserBackupBackend {
    fun sourceDirectoryName(treeUri: Uri): String

    suspend fun saveBackup(backup: FolderBackupEntity)

    suspend fun deleteBackup(id: String)

    fun forgetDiagnostics(backup: FolderBackupEntity)

    fun scanBackupsNow()
}

internal class AndroidBrowserBackupBackend(
    private val application: Application,
    private val store: FileBrowserStore,
    private val transfers: TransferManager,
) : BrowserBackupBackend {
    override fun sourceDirectoryName(treeUri: Uri): String {
        val displayName =
            runCatching {
                val documentUri =
                    DocumentsContract.buildDocumentUriUsingTree(
                        treeUri,
                        DocumentsContract.getTreeDocumentId(treeUri),
                    )
                application.contentResolver
                    .query(
                        documentUri,
                        arrayOf(DocumentsContract.Document.COLUMN_DISPLAY_NAME),
                        null,
                        null,
                        null,
                    )?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }
            }.getOrNull()
        return displayName?.takeIf(String::isNotBlank) ?: sourceNameFromTreeUri(treeUri.toString())
    }

    override suspend fun saveBackup(backup: FolderBackupEntity) = transfers.saveBackup(backup)

    override suspend fun deleteBackup(id: String) = store.deleteBackup(id)

    override fun forgetDiagnostics(backup: FolderBackupEntity) = BackupScanDiagnostics(application).forget(backup)

    override fun scanBackupsNow() = transfers.scanBackupsNow()
}
