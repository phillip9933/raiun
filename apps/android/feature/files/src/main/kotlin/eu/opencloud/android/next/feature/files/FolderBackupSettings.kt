package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.TextFieldValue
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.designsystem.component.HorizontalDivider
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.BackupExclusions
import eu.opencloud.android.next.core.sync.formatBackupDateFolder

@Composable
@Suppress("LongParameterList")
fun FolderBackupSettingsDialog(
    backups: List<FolderBackupEntity>,
    pickerTrail: List<BackupFolderCrumb>,
    pickerFolders: List<ResourceEntity>,
    onDismiss: () -> Unit,
    onAdd: (BackupDraft) -> Unit,
    onDelete: (String) -> Unit,
    onOpenPicker: () -> Unit,
    onOpenFolder: (ResourceEntity) -> Unit,
    onNavigateUp: () -> Unit,
    onCreateFolder: (String) -> Unit,
    sourceDisplayName: String? = null,
    onChooseSource: () -> Unit = {},
) = AlertDialog(
    onDismissRequest = onDismiss,
    text = {
        FolderBackupSettingsContent(
            backups = backups,
            pickerTrail = pickerTrail,
            pickerFolders = pickerFolders,
            onDismiss = onDismiss,
            onAdd = onAdd,
            onDelete = onDelete,
            onOpenPicker = onOpenPicker,
            onOpenFolder = onOpenFolder,
            onNavigateUp = onNavigateUp,
            onCreateFolder = onCreateFolder,
            sourceDisplayName = sourceDisplayName,
            onChooseSource = onChooseSource,
        )
    },
    confirmButton = {},
)

@Composable
@Suppress("LongParameterList", "CyclomaticComplexMethod", "LongMethod", "UnusedParameter")
fun FolderBackupSettingsContent(
    backups: List<FolderBackupEntity>,
    onDismiss: () -> Unit,
    onAdd: (BackupDraft) -> Unit,
    onDelete: (String) -> Unit,
    modifier: Modifier = Modifier,
    pickerTrail: List<BackupFolderCrumb> = emptyList(),
    pickerFolders: List<ResourceEntity> = emptyList(),
    onOpenPicker: () -> Unit = {},
    onOpenPickerSpace: (SpaceEntity) -> Unit = {},
    onOpenPickerShare: (BackupSharedRoot) -> Unit = {},
    onOpenSharedFolder: (BackupSharedFolder) -> Unit = {},
    onOpenFolder: (ResourceEntity) -> Unit = {},
    onNavigateUp: () -> Unit = {},
    onCreateFolder: (String) -> Unit = {},
    initialBackup: FolderBackupEntity? = null,
    transfers: List<TransferEntity> = emptyList(),
    sourceDisplayName: String? = null,
    onChooseSource: () -> Unit = {},
    onBackupPickerPage: (Boolean) -> Unit = {},
    pickerState: FileBrowserUiState = FileBrowserUiState(),
    defaultSpaceId: String? = null,
    requireDestinationBinding: Boolean = false,
) {
    var destination by rememberSaveable(initialBackup?.id) {
        mutableStateOf(
            initialBackup?.destinationPath ?: "/Camera Uploads",
        )
    }
    var showDestinationPicker by rememberSaveable { mutableStateOf(false) }
    var destinationSpaceId by rememberSaveable(initialBackup?.id) {
        mutableStateOf(
            initialBackup?.spaceId ?: defaultSpaceId,
        )
    }
    var destinationKind by rememberSaveable(initialBackup?.id) {
        mutableStateOf(
            initialBackup?.destinationKind ?: "SPACE",
        )
    }
    var sharedShareId by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.sharedShareId) }
    var sharedFolderId by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.sharedFolderId) }
    var destinationName by rememberSaveable(initialBackup?.id) { mutableStateOf<String?>(null) }
    LaunchedEffect(defaultSpaceId, initialBackup?.id) {
        if (initialBackup == null && destinationSpaceId == null) destinationSpaceId = defaultSpaceId
    }
    var showCreateFolder by rememberSaveable { mutableStateOf(false) }
    var mediaType by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.mediaType ?: "IMAGE") }
    var wifiOnly by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.wifiOnly ?: true) }
    var chargingOnly by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.chargingOnly ?: false) }
    var datedFolders by rememberSaveable(initialBackup?.id) {
        mutableStateOf(initialBackup?.dateOrganization?.let { it != "NONE" } ?: false)
    }
    var datePattern by rememberSaveable(initialBackup?.id) {
        mutableStateOf(initialBackupDatePattern(initialBackup?.dateOrganization))
    }
    var showDatePatternEditor by rememberSaveable(initialBackup?.id) { mutableStateOf(false) }
    var backupEnabled by rememberSaveable(initialBackup?.id) { mutableStateOf(initialBackup?.enabled ?: true) }
    var exclusionPatterns by rememberSaveable(initialBackup?.id) {
        mutableStateOf(initialBackup?.exclusionPatterns.orEmpty())
    }
    var showExclusions by rememberSaveable(initialBackup?.id) { mutableStateOf(false) }
    var exclusionRows by rememberSaveable(initialBackup?.id) { mutableStateOf(arrayListOf("")) }
    var exclusionRowIds by rememberSaveable(initialBackup?.id) { mutableStateOf(arrayListOf(0)) }
    var nextExclusionRowId by rememberSaveable(initialBackup?.id) { mutableIntStateOf(1) }
    var focusExclusionRowId by rememberSaveable(initialBackup?.id) { mutableStateOf<Int?>(null) }
    val exclusionError = BackupExclusions.validate(exclusionPatterns)
    val datePreview = formatBackupDateFolder(datePattern, 1_790_687_999_000L)
    Column(modifier = modifier.fillMaxWidth()) {
        Column(
            modifier =
                Modifier
                    .weight(1f, fill = false)
                    .verticalScroll(rememberScrollState())
                    .padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
        ) {
            Text(
                stringResource(
                    if (initialBackup ==
                        null
                    ) {
                        R.string.backup_settings_add
                    } else {
                        R.string.backup_settings_manage
                    },
                ),
                style = MaterialTheme.typography.headlineSmall,
            )
            BackupSwitch(stringResource(R.string.backup_pause_option), !backupEnabled) { backupEnabled = !it }
            if (!backupEnabled) {
                Text(
                    stringResource(
                        if (initialBackup?.enabled == false) {
                            R.string.backup_settings_paused
                        } else {
                            R.string.backup_pause_pending
                        },
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            BackupLocationChoice(
                label = stringResource(R.string.backup_settings_source_folder),
                value =
                    sourceDisplayName
                        ?: initialBackup?.let {
                            it.sourceDisplayName.ifBlank {
                                sourceNameFromTreeUri(
                                    it.sourceTreeUri,
                                )
                            }
                        }
                        ?: stringResource(R.string.backup_settings_source_not_selected),
                action = stringResource(R.string.browser_choose_source_folder),
                onClick = onChooseSource,
            )
            BackupLocationChoice(
                label = stringResource(R.string.backup_settings_destination_folder),
                value =
                    if (destinationKind == "SHARED_FOLDER") {
                        val name =
                            pickerState.backupPickerSharedRoots.firstOrNull { it.shareId == sharedShareId }?.name
                                ?: sharedShareId?.let(pickerState.backupPickerSharedNames::get)
                        val category = stringResource(R.string.backup_destination_shared_with_me)
                        val label = destinationName ?: if (name == null) category else "$category · $name"
                        "$label · $destination"
                    } else {
                        val space = pickerState.spaces.firstOrNull { it.driveId == destinationSpaceId }
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
                        val label = destinationName ?: space?.name?.let { "$category · $it" } ?: category
                        "$label · $destination"
                    },
                action = stringResource(R.string.browser_select_folder),
                onClick = {
                    onOpenPicker()
                    showDestinationPicker = true
                },
            )
            HorizontalDivider()
            Text(stringResource(R.string.backup_settings_files_to_back_up), style = MaterialTheme.typography.titleSmall)
            BackupMediaTypeOptions(mediaType) { mediaType = it }
            Text(
                stringResource(
                    when (mediaType) {
                        "IMAGE" -> R.string.backup_filter_photos_help
                        "VIDEO" -> R.string.backup_filter_videos_help
                        else -> R.string.backup_filter_all_help
                    },
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            HorizontalDivider()
            BackupDateOrganizationOptions(
                wifiOnly = wifiOnly,
                onWifiOnlyChange = { wifiOnly = it },
                chargingOnly = chargingOnly,
                onChargingOnlyChange = { chargingOnly = it },
                enabled = datedFolders,
                pattern = datePattern,
                onEditPattern = { showDatePatternEditor = true },
            )
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(stringResource(R.string.backup_exclusions_label), modifier = Modifier.weight(1f))
                OutlinedButton(onClick = {
                    val patterns = exclusionPatterns.lines().filter(String::isNotBlank).ifEmpty { listOf("") }
                    exclusionRows = ArrayList(patterns)
                    exclusionRowIds = ArrayList(patterns.indices.map { nextExclusionRowId + it })
                    nextExclusionRowId += patterns.size
                    focusExclusionRowId = null
                    showExclusions = true
                }) {
                    Text(stringResource(R.string.backup_exclusions_button))
                }
            }
            if (backups.isNotEmpty() || initialBackup != null) HorizontalDivider()
            backups.forEach { backup -> BackupConfigurationItem(backup = backup, onDelete = { onDelete(backup.id) }) }
            BackupRemoveButton(initialBackup, onDelete, onDismiss)
        }
        HorizontalDivider()
        Row(
            modifier = Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingMd),
            horizontalArrangement = Arrangement.End,
        ) {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.browser_cancel)) }
            Button(
                enabled =
                    (initialBackup != null || sourceDisplayName != null) &&
                        (!requireDestinationBinding || destinationSpaceId != null) &&
                        (!datedFolders || datePreview != null) &&
                        exclusionError == null,
                onClick = {
                    onAdd(
                        BackupDraft(
                            destination,
                            mediaType,
                            wifiOnly,
                            chargingOnly,
                            false,
                            if (datedFolders) datePattern else "NONE",
                            destinationSpaceId,
                            destinationKind,
                            sharedShareId,
                            sharedFolderId,
                            exclusionPatterns,
                            backupEnabled,
                        ),
                    )
                },
            ) {
                Text(stringResource(R.string.browser_save))
            }
        }
    }
    if (showDestinationPicker) {
        BackupDestinationPickerDialog(
            state = pickerState,
            onDismiss = { showDestinationPicker = false },
            onOpenSpace = onOpenPickerSpace,
            onOpenShare = onOpenPickerShare,
            onOpenFolder = onOpenFolder,
            onOpenSharedFolder = onOpenSharedFolder,
            onNavigateUp = onNavigateUp,
            onRetry = onOpenPicker,
            onCreateFolder = { showCreateFolder = true },
            onPage = onBackupPickerPage,
            onSelect = { selected ->
                destination = selected.path
                destinationSpaceId = selected.spaceId
                destinationKind = selected.destinationKind
                sharedShareId = selected.sharedShareId
                sharedFolderId = selected.sharedFolderId
                destinationName = selected.name
                showDestinationPicker = false
            },
        )
    }
    if (showCreateFolder) {
        NameDialog(
            title = stringResource(R.string.browser_new_destination_folder),
            confirm = stringResource(R.string.browser_create),
            onDismiss = { showCreateFolder = false },
        ) { name ->
            onCreateFolder(name)
            showCreateFolder = false
        }
    }
    if (showExclusions) {
        BackupExclusionsDialog(
            rows = exclusionRows,
            rowIds = exclusionRowIds,
            focusRowId = focusExclusionRowId,
            onRowChange = { index, value ->
                exclusionRows =
                    ArrayList(exclusionRows).apply { this[index] = value.replace("\n", "").replace("\r", "") }
            },
            onAddRow = {
                val id = nextExclusionRowId++
                exclusionRows = ArrayList(exclusionRows).apply { add("") }
                exclusionRowIds = ArrayList(exclusionRowIds).apply { add(id) }
                focusExclusionRowId = id
            },
            onRemoveRow = { index ->
                if (focusExclusionRowId == exclusionRowIds[index]) focusExclusionRowId = null
                exclusionRows = ArrayList(exclusionRows).apply { removeAt(index) }
                exclusionRowIds = ArrayList(exclusionRowIds).apply { removeAt(index) }
            },
            onCancel = {
                focusExclusionRowId = null
                showExclusions = false
            },
            onDone = {
                exclusionPatterns = exclusionRows.filter(String::isNotBlank).joinToString("\n")
                focusExclusionRowId = null
                showExclusions = false
            },
        )
    }
    if (showDatePatternEditor) {
        BackupDatePatternDialog(
            enabled = datedFolders,
            pattern = datePattern,
            destination = destination,
            onCancel = { showDatePatternEditor = false },
            onDone = { selectedEnabled, selectedPattern ->
                datedFolders = selectedEnabled
                datePattern = selectedPattern
                showDatePatternEditor = false
            },
        )
    }
}

@Composable
@Suppress("LongParameterList") // Dialog rows and their editor actions are independent inputs.
private fun BackupExclusionsDialog(
    rows: List<String>,
    rowIds: List<Int>,
    focusRowId: Int?,
    onRowChange: (Int, String) -> Unit,
    onAddRow: () -> Unit,
    onRemoveRow: (Int) -> Unit,
    onCancel: () -> Unit,
    onDone: () -> Unit,
) {
    val error = BackupExclusions.validate(rows.filter(String::isNotBlank).joinToString("\n"))
    val listState = rememberLazyListState()
    LaunchedEffect(focusRowId) {
        val index = rowIds.indexOf(focusRowId)
        if (index >= 0) listState.scrollToItem(index)
    }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.backup_exclusions_button)) },
        text = {
            LazyColumn(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .heightIn(max = OpenCloudDimensions.BackupExclusionsListHeight),
                state = listState,
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                itemsIndexed(rows, key = { index, _ -> rowIds[index] }) { index, pattern ->
                    val rowId = rowIds[index]
                    val focusRequester = remember { FocusRequester() }
                    LaunchedEffect(focusRowId, rowId) {
                        if (focusRowId == rowId) {
                            focusRequester.requestFocus()
                        }
                    }
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        OutlinedTextField(
                            value = pattern,
                            onValueChange = { onRowChange(index, it) },
                            label = { Text(stringResource(R.string.backup_exclusions_pattern, index + 1)) },
                            singleLine = true,
                            modifier =
                                Modifier
                                    .weight(1f)
                                    .focusRequester(focusRequester),
                        )
                        IconButton(onClick = { onRemoveRow(index) }) {
                            Icon(
                                Icons.Default.Remove,
                                contentDescription = stringResource(R.string.backup_exclusions_remove, index + 1),
                            )
                        }
                    }
                }
                item(key = "add") {
                    IconButton(onClick = onAddRow) {
                        Icon(Icons.Default.Add, contentDescription = stringResource(R.string.backup_exclusions_add))
                    }
                }
                item(key = "help") {
                    Text(stringResource(R.string.backup_exclusions_help), style = MaterialTheme.typography.bodySmall)
                }
                if (error != null) {
                    item(key = "error") {
                        Text(
                            stringResource(R.string.backup_exclusions_invalid),
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
                item(key = "effect") {
                    Text(stringResource(R.string.backup_exclusions_effect), style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onDone,
                enabled = error == null,
            ) { Text(stringResource(R.string.backup_exclusions_done)) }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.browser_cancel)) } },
    )
}

@Composable
private fun BackupRemoveButton(
    backup: FolderBackupEntity?,
    onDelete: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    backup?.let {
        TextButton(onClick = {
            onDelete(it.id)
            onDismiss()
        }) { Text(stringResource(R.string.browser_remove_backup), color = MaterialTheme.colorScheme.error) }
    }
}

@Composable
@Suppress("LongParameterList") // The option state and callbacks are independent editor controls.
private fun BackupDateOrganizationOptions(
    wifiOnly: Boolean,
    onWifiOnlyChange: (Boolean) -> Unit,
    chargingOnly: Boolean,
    onChargingOnlyChange: (Boolean) -> Unit,
    enabled: Boolean,
    pattern: String,
    onEditPattern: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
        Text(stringResource(R.string.backup_settings_conditions), style = MaterialTheme.typography.titleSmall)
        BackupSwitch(stringResource(R.string.browser_wifi_only), wifiOnly, onWifiOnlyChange)
        BackupSwitch(stringResource(R.string.browser_charging_only), chargingOnly, onChargingOnlyChange)
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text(stringResource(R.string.backup_date_pattern), style = MaterialTheme.typography.bodyMedium)
                Text(
                    if (enabled) pattern else stringResource(R.string.backup_date_off),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            OutlinedButton(onClick = onEditPattern) { Text(stringResource(R.string.backup_date_edit)) }
        }
    }
}

@Composable
private fun BackupDatePatternDialog(
    enabled: Boolean,
    pattern: String,
    destination: String,
    onCancel: () -> Unit,
    onDone: (Boolean, String) -> Unit,
) {
    var selectedEnabled by rememberSaveable(enabled) { mutableStateOf(enabled) }
    var input by rememberSaveable(pattern, stateSaver = TextFieldValue.Saver) {
        mutableStateOf(TextFieldValue(pattern, TextRange(pattern.length)))
    }
    val preview = formatBackupDateFolder(input.text, 1_790_687_999_000L)
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.backup_date_pattern)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                Text(stringResource(R.string.backup_date_editor_help), style = MaterialTheme.typography.bodySmall)
                BackupSwitch(stringResource(R.string.backup_date_folders), selectedEnabled) { selectedEnabled = it }
                OutlinedTextField(
                    value = input,
                    onValueChange = { input = it },
                    label = { Text(stringResource(R.string.backup_date_pattern)) },
                    singleLine = true,
                    isError = preview == null,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(stringResource(R.string.backup_date_presets), style = MaterialTheme.typography.labelMedium)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
                    listOf("[YYYY]/[MM]", "[YYYY]/[MM]/[DD]", "[YYYY]-[MM]-[DD]").forEach { preset ->
                        FilterChip(
                            selected = input.text == preset,
                            onClick = { input = TextFieldValue(preset, TextRange(preset.length)) },
                            label = { Text(preset) },
                        )
                    }
                }
                Text(stringResource(R.string.backup_date_insert_token), style = MaterialTheme.typography.labelMedium)
                listOf(
                    R.string.backup_date_group_year to
                        listOf(
                            Triple("[YYYY]", "2026", R.string.backup_date_token_year),
                            Triple("[YY]", "26", R.string.backup_date_token_short_year),
                        ),
                    R.string.backup_date_group_month to
                        listOf(
                            Triple("[MMMM]", "October", R.string.backup_date_token_month_name),
                            Triple("[MMM]", "Oct", R.string.backup_date_token_short_month_name),
                            Triple("[MM]", "01–12", R.string.backup_date_token_month),
                            Triple("[M]", "1–12", R.string.backup_date_token_short_month),
                        ),
                    R.string.backup_date_group_day to
                        listOf(
                            Triple("[DD]", "01–31", R.string.backup_date_token_day),
                            Triple("[D]", "1–31", R.string.backup_date_token_short_day),
                        ),
                ).forEach { (groupLabel, tokens) ->
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            stringResource(groupLabel),
                            style = MaterialTheme.typography.labelSmall,
                            modifier = Modifier.weight(1f),
                        )
                        FlowRow(
                            modifier = Modifier.weight(4f),
                            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                        ) {
                            tokens.forEach { (token, example, description) ->
                                val descriptionText = stringResource(description)
                                AssistChip(
                                    onClick = {
                                        val start = input.selection.min.coerceIn(0, input.text.length)
                                        val end = input.selection.max.coerceIn(start, input.text.length)
                                        val updated = input.text.replaceRange(start, end, token)
                                        input = TextFieldValue(updated, TextRange(start + token.length))
                                    },
                                    label = { Text(example, style = MaterialTheme.typography.labelSmall) },
                                    modifier = Modifier.semantics { contentDescription = descriptionText },
                                )
                            }
                        }
                    }
                }
                Text(
                    if (preview == null) {
                        stringResource(R.string.backup_date_invalid)
                    } else {
                        stringResource(R.string.backup_date_preview, "$destination/$preview")
                    },
                    style = MaterialTheme.typography.bodySmall,
                    color =
                        if (preview ==
                            null
                        ) {
                            MaterialTheme.colorScheme.error
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                )
                Text(stringResource(R.string.backup_date_fallback), style = MaterialTheme.typography.bodySmall)
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onDone(selectedEnabled, input.text) },
                enabled = !selectedEnabled || preview != null,
            ) {
                Text(stringResource(R.string.backup_exclusions_done))
            }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text(stringResource(R.string.browser_cancel)) } },
    )
}

@Composable
private fun BackupConfigurationItem(
    backup: FolderBackupEntity,
    onDelete: () -> Unit,
) = ListItem(
    headlineContent = {
        BackupPathLine(
            label = stringResource(R.string.browser_local_path_label),
            value = backup.sourceDisplayName.ifBlank { sourceNameFromTreeUri(backup.sourceTreeUri) },
        )
    },
    supportingContent = {
        Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
            BackupPathLine(label = stringResource(R.string.browser_remote_path_label), value = backup.destinationPath)
            Text(
                backupDetails(backup, LocalContext.current),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    },
    trailingContent = {
        IconButton(onClick = onDelete) { Icon(Icons.Default.Delete, stringResource(R.string.browser_remove_backup)) }
    },
)

@Composable
private fun BackupPathLine(
    label: String,
    value: String,
) {
    Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
        Text(label, fontWeight = FontWeight.SemiBold)
        Text(value)
    }
}

@Composable
private fun BackupLocationChoice(
    label: String,
    value: String,
    action: String?,
    onClick: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs)) {
        Text(label, style = MaterialTheme.typography.titleSmall)
        Text(value, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (action != null) TextButton(onClick = onClick) { Text(action) }
    }
}

@Composable
private fun BackupMediaTypeOptions(
    selected: String,
    onSelect: (String) -> Unit,
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
        listOf(
            "IMAGE" to R.string.browser_photo_type,
            "VIDEO" to R.string.browser_video_type,
            "ALL" to R.string.browser_all_files_type,
        ).forEach { (value, labelId) ->
            val label = stringResource(labelId)
            FilterChip(selected = selected == value, onClick = { onSelect(value) }, label = { Text(label) })
        }
    }
}

/** Production callers supply Context; pure callers retain the established English fallback. */
internal fun backupDetails(
    backup: FolderBackupEntity,
    context: android.content.Context? = null,
): String {
    fun label(
        id: Int,
        fallback: String,
    ): String = context?.getString(id) ?: fallback
    val fileType =
        when (backup.mediaType) {
            "IMAGE" -> label(R.string.browser_photo_type, "Photos")
            "VIDEO" -> label(R.string.browser_video_type, "Videos")
            else -> label(R.string.browser_all_files_type, "All files")
        }
    val constraints =
        buildList {
            if (backup.wifiOnly) add(label(R.string.browser_wifi_only, "Wi-Fi only"))
            if (backup.chargingOnly) add(label(R.string.browser_charging, "Charging"))
        }.ifEmpty { listOf(label(R.string.browser_no_restrictions, "No restrictions")) }
    val separator = " ${label(R.string.browser_backup_separator, "•")} "
    return context?.getString(R.string.browser_backup_constraints, fileType, constraints.joinToString(separator))
        ?: "$fileType • ${constraints.joinToString(separator)}"
}

@Composable
private fun BackupSwitch(
    label: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, modifier = Modifier.weight(1f))
        Switch(
            checked = checked,
            onCheckedChange = onCheckedChange,
            modifier = Modifier.semantics { contentDescription = label },
        )
    }
}

data class BackupDraft(
    val destinationPath: String,
    val mediaType: String,
    val wifiOnly: Boolean,
    val chargingOnly: Boolean,
    val deleteAfterUpload: Boolean,
    val dateOrganization: String = "NONE",
    val spaceId: String? = null,
    val destinationKind: String = "SPACE",
    val sharedShareId: String? = null,
    val sharedFolderId: String? = null,
    val exclusionPatterns: String = "",
    val enabled: Boolean = true,
)

private fun initialBackupDatePattern(organization: String?): String =
    when (organization) {
        null, "NONE", "YEAR_MONTH" -> "[YYYY]/[MM]"
        else -> organization
    }
