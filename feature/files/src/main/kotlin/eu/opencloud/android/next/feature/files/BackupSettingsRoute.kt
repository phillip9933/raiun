package eu.opencloud.android.next.feature.files

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.listSaver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongMethod") // The route keeps source permission and editor lifecycle together.
fun BackupSettingsRoute(
    accountId: String,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: FileBrowserViewModel = viewModel(key = "backup-settings-$accountId"),
) {
    val context = LocalContext.current
    val state by viewModel.state.collectAsState()
    var pendingBackup by rememberSaveable(
        accountId,
        stateSaver = backupDraftSaver,
    ) { mutableStateOf<BackupDraft?>(null) }
    var showEditor by rememberSaveable(accountId) { mutableStateOf(false) }
    var editingId by rememberSaveable(accountId) { mutableStateOf<String?>(null) }
    var selectedSourceUri by rememberSaveable(accountId) { mutableStateOf<String?>(null) }
    var sourcePickerAccountId by rememberSaveable(accountId) { mutableStateOf<String?>(null) }
    val editing = state.backups.firstOrNull { it.id == editingId }
    val mediaPermission =
        rememberOriginalMediaPermission(onCancel = { pendingBackup = null }) { files ->
            pendingBackup?.let { draft ->
                viewModel.saveBackup(
                    files.single(),
                    draft,
                )
            }
            pendingBackup = null
        }
    val scanPermission = rememberOriginalMediaPermission { viewModel.scanBackupsNow() }
    val backupLauncher =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
            val activeNewEditor = showEditor && editingId == null && sourcePickerAccountId == accountId
            if (uri != null && activeNewEditor) {
                runCatching {
                    context.contentResolver.takePersistableUriPermission(
                        uri,
                        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION,
                    )
                }
                selectedSourceUri = uri.toString()
            }
            sourcePickerAccountId = null
        }

    LaunchedEffect(accountId) { viewModel.load(accountId) }
    Scaffold(
        modifier = modifier,
        floatingActionButton = {
            AddBackupButton {
                editingId = null
                selectedSourceUri = null
                sourcePickerAccountId = null
                showEditor = true
            }
        },
        topBar = {
            BackupSettingsTopBar(
                onNavigateBack = onNavigateBack,
                canScan = state.backups.isNotEmpty(),
                onScan = { scanPermission(state.backups.map { android.net.Uri.parse(it.sourceTreeUri) }) },
            )
        },
    ) { padding ->
        BackupOverview(
            backups = state.backups,
            spaces = state.spaces,
            sharedRoots = state.backupPickerSharedRoots,
            sharedNames = state.backupPickerSharedNames,
            transfers = state.transfers,
            onManage = { backup ->
                editingId = backup.id
                showEditor = true
            },
            modifier = Modifier.padding(padding),
        )
    }
    if (showEditor) {
        BackupEditorDialog {
            FolderBackupSettingsContent(
                backups = emptyList(),
                initialBackup = state.backups.firstOrNull { it.id == editing?.id } ?: editing,
                transfers = state.transfers,
                sourceDisplayName = selectedSourceUri?.let(::sourceNameFromTreeUri),
                onChooseSource = {
                    sourcePickerAccountId = accountId
                    backupLauncher.launch(null)
                },
                pickerTrail = state.backupPickerTrail,
                pickerFolders = state.backupPickerResources,
                pickerState = state,
                defaultSpaceId = state.spaces.firstOrNull { it.type.equals("personal", true) }?.driveId,
                requireDestinationBinding = true,
                onDismiss = {
                    showEditor = false
                    selectedSourceUri = null
                    sourcePickerAccountId = null
                },
                onAdd = { draft ->
                    val existing = editing
                    if (existing != null) {
                        viewModel.updateBackup(existing, draft)
                    } else {
                        selectedSourceUri?.let { source ->
                            pendingBackup = draft
                            mediaPermission(listOf(android.net.Uri.parse(source)))
                        }
                    }
                    showEditor = false
                    selectedSourceUri = null
                    sourcePickerAccountId = null
                },
                onDelete = viewModel::deleteBackup,
                onOpenPicker = viewModel::openBackupPicker,
                onOpenPickerSpace = viewModel::openBackupPickerSpace,
                onOpenPickerShare = viewModel::openBackupPickerShare,
                onOpenSharedFolder = viewModel::openBackupPickerSharedFolder,
                onOpenFolder = viewModel::openBackupPickerFolder,
                onNavigateUp = viewModel::navigateBackupPickerUp,
                onCreateFolder = viewModel::createBackupPickerFolder,
            )
        }
    }
    state.error?.let { message ->
        AlertDialog(onDismissRequest = viewModel::clearMessage, text = { Text(message) }, confirmButton = {
            TextButton(onClick = viewModel::clearMessage) { Text(stringResource(R.string.backup_settings_ok)) }
        })
    }
}

@Composable
@Suppress("LongParameterList") // Overview data and callbacks are independent UI inputs.
fun BackupOverview(
    backups: List<FolderBackupEntity>,
    onManage: (FolderBackupEntity) -> Unit,
    modifier: Modifier = Modifier,
    transfers: List<eu.opencloud.android.next.core.database.TransferEntity> = emptyList(),
    spaces: List<SpaceEntity> = emptyList(),
    sharedRoots: List<BackupSharedRoot> = emptyList(),
    sharedNames: Map<String, String> = emptyMap(),
) {
    val backupListDescription = stringResource(R.string.backup_settings_active_configurations)
    LazyColumn(
        modifier.fillMaxSize().padding(horizontal = OpenCloudDimensions.SpacingMd).semantics {
            contentDescription = backupListDescription
        },
    ) {
        if (backups.isEmpty()) {
            item {
                Text(
                    stringResource(R.string.backup_settings_empty_description),
                    Modifier.padding(vertical = OpenCloudDimensions.SpacingMd),
                )
            }
        }
        items(backups, key = { it.id }) { backup ->
            ListItem(
                headlineContent = {
                    Text(
                        backup.sourceDisplayName.ifBlank { sourceNameFromTreeUri(backup.sourceTreeUri) },
                    )
                },
                supportingContent = {
                    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
                        Text(backupDestinationLabel(backup, spaces, sharedRoots, sharedNames))
                        Text(backupDetails(backup, LocalContext.current))
                        BackupSyncInfo(backup, transfers)
                    }
                },
                trailingContent = {
                    TextButton(onClick = { onManage(backup) }) { Text(stringResource(R.string.backup_settings_manage)) }
                },
            )
        }
    }
}

@Composable
private fun backupDestinationLabel(
    backup: FolderBackupEntity,
    spaces: List<SpaceEntity>,
    roots: List<BackupSharedRoot>,
    sharedNames: Map<String, String>,
): String {
    val name =
        if (backup.destinationKind == "SHARED_FOLDER") {
            val category = stringResource(R.string.backup_destination_shared_with_me)
            val root =
                roots.firstOrNull { it.shareId == backup.sharedShareId }?.name
                    ?: backup.sharedShareId?.let(sharedNames::get)
            if (root == null) category else "$category · $root"
        } else {
            val space = spaces.firstOrNull { it.driveId == backup.spaceId }
            val category =
                stringResource(
                    if (space?.type.equals(
                            "personal",
                            true,
                        )
                    ) {
                        R.string.backup_destination_personal
                    } else {
                        R.string.backup_destination_spaces
                    },
                )
            if (space == null) category else "$category · ${space.name}"
        }
    return "$name · ${backup.destinationPath}"
}

private val backupDraftSaver =
    listSaver<BackupDraft?, Any>(
        save = { draft ->
            draft?.let {
                listOf(
                    it.destinationPath,
                    it.mediaType,
                    it.wifiOnly,
                    it.chargingOnly,
                    it.deleteAfterUpload,
                    it.dateOrganization,
                    it.spaceId ?: "",
                    it.destinationKind,
                    it.sharedShareId ?: "",
                    it.sharedFolderId ?: "",
                    it.exclusionPatterns,
                    it.enabled,
                )
            }
                ?: emptyList()
        },
        restore = { values ->
            if (values.size in 10..12) {
                BackupDraft(
                    values[0] as String,
                    values[1] as String,
                    values[2] as Boolean,
                    values[3] as Boolean,
                    values[4] as Boolean,
                    values[5] as String,
                    (values[6] as String).ifBlank { null },
                    values[7] as String,
                    (values[8] as String).ifBlank { null },
                    (values[9] as String).ifBlank { null },
                    (values.getOrNull(10) as? String).orEmpty(),
                    (values.getOrNull(11) as? Boolean) ?: true,
                )
            } else {
                null
            }
        },
    )

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun BackupSettingsTopBar(
    onNavigateBack: () -> Unit,
    canScan: Boolean,
    onScan: () -> Unit,
) {
    TopAppBar(
        title = { Text(stringResource(R.string.backup_settings_title)) },
        actions = {
            IconButton(onClick = onScan, enabled = canScan) {
                Icon(
                    Icons.Default.Refresh,
                    contentDescription = stringResource(R.string.backup_settings_scan_accessibility),
                )
            }
        },
        navigationIcon = {
            IconButton(onClick = onNavigateBack) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack,
                    contentDescription = stringResource(R.string.backup_settings_back),
                )
            }
        },
    )
}

@Composable
private fun AddBackupButton(onClick: () -> Unit) {
    FloatingActionButton(onClick = onClick) {
        Icon(Icons.Default.Add, contentDescription = stringResource(R.string.backup_settings_add_accessibility))
    }
}
