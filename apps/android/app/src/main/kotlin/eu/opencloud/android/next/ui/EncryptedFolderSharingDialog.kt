package eu.opencloud.android.next.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.RemoteShare
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.EncryptedLocationManagementRepository
import eu.opencloud.android.next.core.sync.VaultLocation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Named collaborators on one unlocked encrypted folder root; no link or descendant sharing. */
@Composable
// Dialog modes share one secure window; each write is guarded and has explicit confirmation/error paths.
@Suppress("LongMethod", "TooGenericExceptionCaught", "CyclomaticComplexMethod", "LongParameterList")
internal fun EncryptedFolderSharingDialog(
    accountId: String,
    location: VaultLocation,
    isUnlocked: () -> Boolean,
    onClose: () -> Unit,
    onInvalidate: () -> Unit = {},
    backend: FolderShareBackend? = null,
) {
    val context = LocalContext.current
    val actions = backend ?: remember(context) { AndroidFolderShareBackend(context) }
    val scope = rememberCoroutineScope()
    var activeJob by remember { mutableStateOf<Job?>(null) }
    var shares by remember(accountId, location) { mutableStateOf(emptyList<RemoteShare>()) }
    var recipients by remember(accountId, location) { mutableStateOf(emptyList<ShareRecipient>()) }
    var query by remember(accountId, location) { mutableStateOf("") }
    var recipient by remember(accountId, location) { mutableStateOf<ShareRecipient?>(null) }
    var selectedShare by remember(accountId, location) { mutableStateOf<RemoteShare?>(null) }
    var adding by remember(accountId, location) { mutableStateOf(false) }
    var confirmingRemoval by remember(accountId, location) { mutableStateOf(false) }
    var permissions by remember(accountId, location) { mutableStateOf(VIEWER) }
    var busy by remember(accountId, location) { mutableStateOf(true) }
    var error by remember(accountId, location) { mutableStateOf<String?>(null) }
    var uncertainWrite by remember(accountId, location) { mutableStateOf(false) }

    fun start(
        write: Boolean = false,
        action: suspend () -> Unit,
    ) {
        activeJob?.cancel()
        busy = true
        error = null
        activeJob =
            scope.launch {
                try {
                    action()
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    if (write) uncertainWrite = true
                    val typed = failure.toOpenCloudError()
                    error = typed.safeMessage(context)
                    if (typed.invalidatesEncryptedFolder()) onInvalidate()
                } finally {
                    busy = false
                }
            }
    }

    fun refresh() {
        start {
            shares =
                withContext(Dispatchers.IO) {
                    actions.list(accountId, location, isUnlocked)
                }.filter { it.isNamedFolderRootShare(location) }
            selectedShare = null
            adding = false
            confirmingRemoval = false
            uncertainWrite = false
        }
    }

    fun finishEditing() {
        selectedShare = null
        adding = false
        confirmingRemoval = false
        recipients = emptyList()
        recipient = null
        query = ""
        permissions = VIEWER
        error = null
    }

    DisposableEffect(accountId, location) {
        onDispose { activeJob?.cancel() }
    }
    LaunchedEffect(accountId, location) { refresh() }

    val editing = adding || selectedShare != null
    val canAct = !busy && !uncertainWrite && isUnlocked()
    val chosenShare = selectedShare
    val chosenRecipient = recipient
    val canSave =
        canAct &&
            (
                confirmingRemoval ||
                    (
                        permissions in setOf(VIEWER, EDITOR, EDITOR_RESHARE) &&
                            (!adding || chosenRecipient != null)
                    )
            ) &&
            (!adding || permissions != EDITOR_RESHARE)

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(stringResource(R.string.vault_folder_sharing_title)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                Text(location.title, style = MaterialTheme.typography.titleMedium)
                Text(stringResource(R.string.vault_folder_sharing_warning))
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                if (uncertainWrite) {
                    Text(stringResource(R.string.vault_folder_sharing_uncertain))
                    FilledTonalButton(enabled = !busy, onClick = ::refresh) {
                        Text(stringResource(R.string.vault_refresh))
                    }
                }
                when {
                    adding -> {
                        OutlinedTextField(
                            value = query,
                            onValueChange = {
                                query = it
                                recipient = null
                                recipients = emptyList()
                            },
                            label = { Text(stringResource(R.string.vault_folder_sharing_search)) },
                            enabled = canAct,
                            singleLine = true,
                        )
                        OutlinedButton(enabled = canAct && query.trim().length >= 2, onClick = {
                            val search = query.trim()
                            start {
                                recipients =
                                    withContext(Dispatchers.IO) {
                                        actions.search(accountId, location, search, isUnlocked)
                                    }.filter { it.type == OcsShareType.USER || it.type == OcsShareType.GROUP }
                            }
                        }) { Text(stringResource(R.string.vault_folder_sharing_search)) }
                        recipients.forEach { candidate ->
                            FilterChip(
                                selected = candidate == recipient,
                                onClick = { recipient = candidate },
                                label = { Text(candidate.label) },
                                enabled = canAct,
                            )
                        }
                        FolderSharePermissions(permissions, allowReshare = false, enabled = canAct) { permissions = it }
                    }
                    chosenShare != null -> {
                        Text(
                            chosenShare.displayName ?: chosenShare.shareWith.orEmpty(),
                            style = MaterialTheme.typography.titleSmall,
                        )
                        Text(
                            stringResource(
                                if (chosenShare.type == OcsShareType.GROUP) {
                                    R.string.vault_folder_sharing_group
                                } else {
                                    R.string.vault_folder_sharing_person
                                },
                            ),
                        )
                        if (confirmingRemoval) {
                            Text(stringResource(R.string.vault_folder_sharing_remove_confirm))
                        } else {
                            FolderSharePermissions(
                                permissions,
                                allowReshare = chosenShare.permissions == EDITOR_RESHARE,
                                enabled = canAct,
                            ) { permissions = it }
                            if (chosenShare.permissions !in setOf(VIEWER, EDITOR, EDITOR_RESHARE)) {
                                Text(stringResource(R.string.vault_folder_sharing_custom_permissions))
                            }
                            OutlinedButton(enabled = canAct, onClick = { confirmingRemoval = true }) {
                                Text(
                                    stringResource(R.string.vault_folder_sharing_remove),
                                    color = MaterialTheme.colorScheme.error,
                                )
                            }
                        }
                    }
                    else -> {
                        Text(
                            stringResource(R.string.vault_folder_sharing_people),
                            style = MaterialTheme.typography.titleSmall,
                        )
                        if (shares.isEmpty() && !busy) Text(stringResource(R.string.vault_folder_sharing_empty))
                        shares.forEach { share ->
                            OutlinedButton(enabled = canAct, onClick = {
                                selectedShare = share
                                permissions = share.permissions
                                confirmingRemoval = false
                            }) {
                                Text(share.displayName ?: share.shareWith.orEmpty())
                            }
                        }
                        OutlinedButton(enabled = canAct, onClick = {
                            adding = true
                            selectedShare = null
                            recipient = null
                            recipients = emptyList()
                            query = ""
                            permissions = VIEWER
                        }) { Text(stringResource(R.string.vault_folder_sharing_add)) }
                    }
                }
            }
        },
        confirmButton = {
            if (editing) {
                Button(enabled = canSave, onClick = {
                    val remove = confirmingRemoval
                    val share = chosenShare
                    val target = chosenRecipient
                    val chosenPermissions = permissions
                    start(write = true) {
                        shares =
                            withContext(Dispatchers.IO) {
                                when {
                                    remove -> actions.remove(accountId, location, requireNotNull(share).id, isUnlocked)
                                    adding ->
                                        actions.add(
                                            accountId,
                                            location,
                                            requireNotNull(target),
                                            chosenPermissions,
                                            isUnlocked,
                                        )
                                    else ->
                                        actions.update(
                                            accountId,
                                            location,
                                            requireNotNull(share).id,
                                            chosenPermissions,
                                            isUnlocked,
                                        )
                                }
                                actions.list(accountId, location, isUnlocked)
                            }.filter { it.isNamedFolderRootShare(location) }
                        uncertainWrite = false
                        finishEditing()
                    }
                }) {
                    Text(
                        stringResource(
                            if (confirmingRemoval) R.string.vault_folder_sharing_remove else R.string.vault_manage_save,
                        ),
                    )
                }
            } else {
                TextButton(enabled = !busy, onClick = onClose) { Text(stringResource(R.string.vault_close)) }
            }
        },
        dismissButton = {
            if (editing) {
                TextButton(enabled = !busy, onClick = ::finishEditing) { Text(stringResource(R.string.vault_cancel)) }
            } else {
                FilledTonalButton(enabled = !busy, onClick = ::refresh) { Text(stringResource(R.string.vault_refresh)) }
            }
        },
    )
}

@Composable
private fun FolderSharePermissions(
    selected: Int,
    allowReshare: Boolean,
    enabled: Boolean,
    onSelect: (Int) -> Unit,
) {
    Column {
        Text(stringResource(R.string.vault_folder_sharing_permissions))
        FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
            FilterChip(
                selected = selected == VIEWER,
                onClick = { onSelect(VIEWER) },
                label = { Text(stringResource(R.string.vault_folder_sharing_viewer)) },
                enabled = enabled,
            )
            FilterChip(
                selected = selected == EDITOR,
                onClick = { onSelect(EDITOR) },
                label = { Text(stringResource(R.string.vault_folder_sharing_editor)) },
                enabled = enabled,
            )
            if (allowReshare) {
                FilterChip(
                    selected = selected == EDITOR_RESHARE,
                    onClick = { onSelect(EDITOR_RESHARE) },
                    label = { Text(stringResource(R.string.vault_folder_sharing_editor_reshare)) },
                    enabled = enabled,
                )
            }
        }
    }
}

private const val VIEWER = 1
private const val EDITOR = 15
private const val EDITOR_RESHARE = 31

private fun RemoteShare.isNamedFolderRootShare(location: VaultLocation): Boolean =
    isFolder &&
        resourceId == location.remoteVaultId &&
        (type == OcsShareType.USER || type == OcsShareType.GROUP)

internal fun OpenCloudError.invalidatesEncryptedFolder(): Boolean =
    this == OpenCloudError.AuthenticationRequired ||
        this == OpenCloudError.AccessDenied ||
        this == OpenCloudError.PreconditionFailed ||
        this == OpenCloudError.NotFound

internal interface FolderShareBackend {
    suspend fun list(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): List<RemoteShare>

    suspend fun search(
        accountId: String,
        location: VaultLocation,
        query: String,
        isUnlocked: () -> Boolean,
    ): List<ShareRecipient>

    suspend fun add(
        accountId: String,
        location: VaultLocation,
        recipient: ShareRecipient,
        permissions: Int,
        isUnlocked: () -> Boolean,
    )

    suspend fun update(
        accountId: String,
        location: VaultLocation,
        shareId: String,
        permissions: Int,
        isUnlocked: () -> Boolean,
    )

    suspend fun remove(
        accountId: String,
        location: VaultLocation,
        shareId: String,
        isUnlocked: () -> Boolean,
    )
}

private class AndroidFolderShareBackend(
    context: android.content.Context,
) : FolderShareBackend {
    private val repository = EncryptedLocationManagementRepository(context)

    override suspend fun list(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ) = repository.listFolderRootShares(accountId, location, isUnlocked)

    override suspend fun search(
        accountId: String,
        location: VaultLocation,
        query: String,
        isUnlocked: () -> Boolean,
    ) = repository.searchRecipients(accountId, location, query, isUnlocked)

    override suspend fun add(
        accountId: String,
        location: VaultLocation,
        recipient: ShareRecipient,
        permissions: Int,
        isUnlocked: () -> Boolean,
    ) {
        repository.addFolderRootShare(accountId, location, recipient, permissions, isUnlocked)
    }

    override suspend fun update(
        accountId: String,
        location: VaultLocation,
        shareId: String,
        permissions: Int,
        isUnlocked: () -> Boolean,
    ) {
        repository.updateFolderRootShare(accountId, location, shareId, permissions, isUnlocked)
    }

    override suspend fun remove(
        accountId: String,
        location: VaultLocation,
        shareId: String,
        isUnlocked: () -> Boolean,
    ) {
        repository.removeFolderRootShare(accountId, location, shareId, isUnlocked)
    }
}
