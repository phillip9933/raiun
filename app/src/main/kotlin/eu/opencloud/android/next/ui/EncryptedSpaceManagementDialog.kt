package eu.opencloud.android.next.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.SpaceMember
import eu.opencloud.android.next.core.network.SpaceMembers
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.EncryptedLocationManagementRepository
import eu.opencloud.android.next.core.sync.EncryptedSpaceDetails
import eu.opencloud.android.next.core.sync.VaultLocation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Manages a Space's metadata and membership while its encrypted root is unlocked. */
@Composable
// Dialog modes share one secure window; each write is guarded and has explicit confirmation/error paths.
@Suppress("LongMethod", "TooGenericExceptionCaught", "CyclomaticComplexMethod", "LongParameterList")
internal fun EncryptedSpaceManagementDialog(
    accountId: String,
    location: VaultLocation,
    isUnlocked: () -> Boolean,
    onClose: () -> Unit,
    onChange: (VaultLocation) -> Unit,
    actionsOverride: EncryptedSpaceManagementActions? = null,
    onInvalidate: () -> Unit = {},
    onLifecycleChange: (VaultLocation?) -> Unit = {},
) {
    val context = LocalContext.current
    val actions =
        actionsOverride ?: remember(context) {
            EncryptedSpaceManagementRepositoryActions(EncryptedLocationManagementRepository(context))
        }
    val scope = rememberCoroutineScope()
    var activeJob by remember { mutableStateOf<Job?>(null) }
    var details by remember(accountId, location) { mutableStateOf<EncryptedSpaceDetails?>(null) }
    var members by remember(accountId, location) { mutableStateOf(SpaceMembers(emptyList(), emptyList())) }
    var busy by remember(accountId, location) { mutableStateOf(true) }
    var error by remember(accountId, location) { mutableStateOf<String?>(null) }
    var uncertainWrite by remember(accountId, location) { mutableStateOf(false) }
    var editingMetadata by remember(accountId, location) { mutableStateOf(false) }
    var name by remember(accountId, location) { mutableStateOf("") }
    var subtitle by remember(accountId, location) { mutableStateOf("") }
    var quotaMiB by remember(accountId, location) { mutableStateOf("") }
    var selectedMember by remember(accountId, location) { mutableStateOf<SpaceMember?>(null) }
    var adding by remember(accountId, location) { mutableStateOf(false) }
    var confirmRemoval by remember(accountId, location) { mutableStateOf(false) }
    var query by remember(accountId, location) { mutableStateOf("") }
    var recipients by remember(accountId, location) { mutableStateOf(emptyList<ShareRecipient>()) }
    var recipient by remember(accountId, location) { mutableStateOf<ShareRecipient?>(null) }
    var role by remember(accountId, location) { mutableStateOf<String?>(null) }
    var confirmDisable by remember(accountId, location) { mutableStateOf(false) }

    fun start(action: suspend () -> Unit) {
        if (!isUnlocked()) {
            error = OpenCloudError.AccessDenied.safeMessage(context)
            onInvalidate()
            return
        }
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
                    if (failure.toOpenCloudError().invalidatesEncryptedSpaceSession()) onInvalidate()
                    error = failure.toOpenCloudError().safeMessage(context)
                } finally {
                    busy = false
                }
            }
    }

    fun refresh() {
        start {
            val fetched =
                withContext(Dispatchers.IO) {
                    actions.spaceDetails(accountId, location, isUnlocked)
                }
            details = fetched
            name = fetched.name
            subtitle = fetched.subtitle.orEmpty()
            quotaMiB = ""
            members =
                withContext(Dispatchers.IO) {
                    actions.listMembers(accountId, location, isUnlocked)
                }
            uncertainWrite = false
            onChange(fetched.location)
        }
    }

    DisposableEffect(accountId, location) {
        onDispose { activeJob?.cancel() }
    }
    LaunchedEffect(accountId, location) { refresh() }

    val metadataValid =
        name.isNotBlank() &&
            (
                quotaMiB.isBlank() ||
                    quotaMiB.toLongOrNull()?.let { it >= 0 && it <= Long.MAX_VALUE / BYTES_PER_MIB } == true
            )
    val memberEditing = selectedMember != null || adding
    val canSaveMember = !busy && !uncertainWrite && (confirmRemoval || (role != null && (!adding || recipient != null)))

    AlertDialog(
        onDismissRequest = { if (!busy) onClose() },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        title = { Text(stringResource(R.string.vault_manage_space_title)) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                details?.let { Text(it.name, style = MaterialTheme.typography.titleMedium) }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                error?.let { Text(it) }
                if (uncertainWrite) {
                    Text(stringResource(R.string.vault_manage_space_uncertain))
                    TextButton(
                        enabled = !busy,
                        onClick = { refresh() },
                    ) { Text(stringResource(R.string.vault_refresh)) }
                }

                if (memberEditing) {
                    if (adding) {
                        OutlinedTextField(
                            value = query,
                            onValueChange = {
                                query = it
                                recipient = null
                                recipients = emptyList()
                            },
                            label = { Text(stringResource(R.string.vault_manage_member_search)) },
                            enabled = !busy,
                            singleLine = true,
                        )
                        TextButton(enabled = !busy && query.trim().length >= 2, onClick = {
                            start {
                                recipients =
                                    withContext(Dispatchers.IO) {
                                        actions.searchRecipients(accountId, location, query.trim(), isUnlocked)
                                    }
                            }
                        }) { Text(stringResource(R.string.vault_manage_member_search)) }
                        recipients.forEach { item ->
                            FilterChip(
                                selected = item == recipient,
                                onClick = { recipient = item },
                                label = { Text(item.label) },
                                enabled = !busy,
                            )
                        }
                    } else {
                        selectedMember?.let { Text(it.name, style = MaterialTheme.typography.titleSmall) }
                    }
                    Text(stringResource(R.string.vault_manage_member_role))
                    RoleChoices(members, role, busy) { role = it }
                    if (selectedMember != null && !confirmRemoval) {
                        TextButton(enabled = !busy, onClick = { confirmRemoval = true }) {
                            Text(stringResource(R.string.vault_manage_member_remove))
                        }
                    }
                    if (confirmRemoval) {
                        Text(
                            stringResource(
                                R.string.vault_manage_member_remove_confirm,
                                selectedMember?.name.orEmpty(),
                            ),
                        )
                        Text(stringResource(R.string.vault_manage_membership_warning))
                    }
                } else if (editingMetadata) {
                    OutlinedTextField(
                        name,
                        { name = it },
                        label = { Text(stringResource(R.string.vault_manage_name)) },
                        enabled = !busy,
                        singleLine = true,
                    )
                    OutlinedTextField(
                        subtitle,
                        { subtitle = it },
                        label = { Text(stringResource(R.string.vault_manage_description)) },
                        enabled = !busy,
                        singleLine = true,
                    )
                    OutlinedTextField(
                        quotaMiB,
                        { input -> if (input.all(Char::isDigit)) quotaMiB = input },
                        label = { Text(stringResource(R.string.vault_manage_quota_mib)) },
                        enabled = !busy,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        singleLine = true,
                    )
                    Text(stringResource(R.string.vault_manage_quota_help))
                } else {
                    details?.let { MetadataSummary(it) }
                    OutlinedButton(enabled = !busy, onClick = { confirmDisable = true }) {
                        Text(stringResource(R.string.vault_manage_disable_space))
                    }
                    OutlinedButton(enabled = !busy, onClick = { editingMetadata = true }) {
                        Text(stringResource(R.string.vault_manage_edit_details))
                    }
                    Text(stringResource(R.string.vault_manage_members))
                    Text(stringResource(R.string.vault_manage_membership_warning))
                    members.members.forEach { member ->
                        val roleNames = member.roles.map { id -> members.roles.firstOrNull { it.id == id }?.name ?: id }
                        OutlinedButton(enabled = !busy, onClick = {
                            selectedMember = member
                            role = member.roles.firstOrNull { memberRole -> members.roles.any { it.id == memberRole } }
                            confirmRemoval = false
                        }) { Text("${member.name} · ${roleNames.joinToString()}") }
                    }
                    if (members.roles.isNotEmpty()) {
                        OutlinedButton(enabled = !busy, onClick = {
                            adding = true
                            selectedMember = null
                            recipient = null
                            role = null
                            recipients = emptyList()
                            query = ""
                        }) { Text(stringResource(R.string.vault_manage_member_add)) }
                    }
                }
            }
        },
        confirmButton = {
            when {
                memberEditing ->
                    TextButton(enabled = canSaveMember, onClick = {
                        val selected = selectedMember
                        val chosenRecipient = recipient
                        val selectedRole = role
                        val remove = confirmRemoval
                        start {
                            uncertainWrite = true
                            members =
                                withContext(Dispatchers.IO) {
                                    when {
                                        remove ->
                                            actions.removeMember(
                                                accountId,
                                                location,
                                                requireNotNull(selected).id,
                                                isUnlocked,
                                            )
                                        adding ->
                                            actions.addMember(
                                                accountId,
                                                location,
                                                requireNotNull(chosenRecipient),
                                                requireNotNull(selectedRole),
                                                isUnlocked,
                                            )
                                        else ->
                                            actions.changeMemberRole(
                                                accountId,
                                                location,
                                                requireNotNull(selected).id,
                                                requireNotNull(selectedRole),
                                                isUnlocked,
                                            )
                                    }
                                    actions.listMembers(accountId, location, isUnlocked)
                                }
                            selectedMember = null
                            adding = false
                            confirmRemoval = false
                            uncertainWrite = false
                            role = null
                            recipients = emptyList()
                        }
                    }) {
                        Text(
                            stringResource(
                                if (confirmRemoval) R.string.vault_manage_member_remove else R.string.vault_manage_save,
                            ),
                        )
                    }
                editingMetadata ->
                    TextButton(enabled = !busy && !uncertainWrite && metadataValid, onClick = {
                        val cleanName = name.trim()
                        val cleanSubtitle = subtitle.trim()
                        val quotaBytes = quotaMiB.toLongOrNull()?.times(BYTES_PER_MIB)
                        start {
                            try {
                                val updated =
                                    withContext(Dispatchers.IO) {
                                        actions.updateSpace(
                                            accountId,
                                            location,
                                            isUnlocked,
                                            name = cleanName,
                                            subtitle = cleanSubtitle,
                                            quotaBytes = quotaBytes,
                                        )
                                    }
                                details = updated
                                name = updated.name
                                subtitle = updated.subtitle.orEmpty()
                                quotaMiB = ""
                                editingMetadata = false
                                uncertainWrite = false
                                onChange(updated.location)
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (failure: Exception) {
                                uncertainWrite = true
                                if (failure.toOpenCloudError().invalidatesEncryptedSpaceSession()) onInvalidate()
                                error = failure.toOpenCloudError().safeMessage(context)
                            }
                        }
                    }) { Text(stringResource(R.string.vault_manage_save)) }
                else -> TextButton(enabled = !busy, onClick = onClose) { Text(stringResource(R.string.vault_close)) }
            }
        },
        dismissButton = {
            when {
                memberEditing || editingMetadata ->
                    TextButton(enabled = !busy, onClick = {
                        if (memberEditing) {
                            selectedMember = null
                            adding = false
                            confirmRemoval = false
                            role = null
                            recipients = emptyList()
                        }
                        if (editingMetadata) {
                            editingMetadata = false
                            details?.let {
                                name = it.name
                                subtitle = it.subtitle.orEmpty()
                                quotaMiB = ""
                            }
                        }
                        error = null
                    }) { Text(stringResource(R.string.vault_cancel)) }
                else ->
                    TextButton(
                        enabled = !busy,
                        onClick = { refresh() },
                    ) { Text(stringResource(R.string.vault_refresh)) }
            }
        },
    )
    if (confirmDisable) {
        AlertDialog(
            onDismissRequest = { if (!busy) confirmDisable = false },
            properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
            title = { Text(stringResource(R.string.vault_manage_disable_space)) },
            text = { Text(stringResource(R.string.vault_manage_disable_confirm)) },
            confirmButton = {
                Button(enabled = !busy, onClick = {
                    start {
                        val disabled =
                            withContext(Dispatchers.IO) {
                                actions.disableSpace(accountId, location, isUnlocked)
                            }
                        onLifecycleChange(disabled)
                        onClose()
                    }
                }) { Text(stringResource(R.string.vault_manage_disable_confirm_action)) }
            },
            dismissButton = {
                TextButton(enabled = !busy, onClick = { confirmDisable = false }) {
                    Text(stringResource(R.string.vault_cancel))
                }
            },
        )
    }
}

@Composable
private fun RoleChoices(
    data: SpaceMembers,
    selected: String?,
    busy: Boolean,
    onSelect: (String) -> Unit,
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        data.roles.forEach { item ->
            FilterChip(selected == item.id, { onSelect(item.id) }, { Text(item.name) }, enabled = !busy)
        }
    }
}

@Composable
private fun MetadataSummary(details: EncryptedSpaceDetails) {
    Column {
        Text(
            stringResource(
                R.string.vault_manage_owner,
                details.ownerName ?: stringResource(R.string.vault_manage_unknown),
            ),
        )
        details.subtitle?.takeIf(String::isNotBlank)?.let {
            Text(stringResource(R.string.vault_manage_description_value, it))
        }
        details.quotaBytes?.let { quota ->
            Text(stringResource(R.string.vault_manage_quota_value, quota / BYTES_PER_MIB))
            details.quotaUsedBytes?.let { Text(stringResource(R.string.vault_manage_used_value, it / BYTES_PER_MIB)) }
            details.quotaRemainingBytes?.let {
                Text(stringResource(R.string.vault_manage_remaining_value, it / BYTES_PER_MIB))
            }
        }
    }
}

private const val BYTES_PER_MIB = 1_048_576L

private fun OpenCloudError.invalidatesEncryptedSpaceSession(): Boolean =
    this == OpenCloudError.AuthenticationRequired ||
        this == OpenCloudError.AccessDenied ||
        this == OpenCloudError.PreconditionFailed ||
        this == OpenCloudError.NotFound

/** Narrow seam for deterministic dialog tests; production delegates to the security-checking repository. */
internal interface EncryptedSpaceManagementActions {
    suspend fun disableSpace(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): VaultLocation

    suspend fun spaceDetails(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): EncryptedSpaceDetails

    @Suppress("LongParameterList") // Mirrors the guarded repository metadata update.
    suspend fun updateSpace(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
        name: String? = null,
        subtitle: String? = null,
        quotaBytes: Long? = null,
    ): EncryptedSpaceDetails

    suspend fun listMembers(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ): SpaceMembers

    suspend fun searchRecipients(
        accountId: String,
        location: VaultLocation,
        query: String,
        isUnlocked: () -> Boolean,
    ): List<ShareRecipient>

    suspend fun addMember(
        accountId: String,
        location: VaultLocation,
        recipient: ShareRecipient,
        role: String,
        isUnlocked: () -> Boolean,
    )

    suspend fun changeMemberRole(
        accountId: String,
        location: VaultLocation,
        permissionId: String,
        role: String,
        isUnlocked: () -> Boolean,
    )

    suspend fun removeMember(
        accountId: String,
        location: VaultLocation,
        permissionId: String,
        isUnlocked: () -> Boolean,
    )
}

private class EncryptedSpaceManagementRepositoryActions(
    private val repository: EncryptedLocationManagementRepository,
) : EncryptedSpaceManagementActions {
    override suspend fun disableSpace(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ) = repository.disableSpace(accountId, location, isUnlocked)

    override suspend fun spaceDetails(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ) = repository.spaceDetails(accountId, location, isUnlocked)

    override suspend fun updateSpace(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
        name: String?,
        subtitle: String?,
        quotaBytes: Long?,
    ) = repository.updateSpace(accountId, location, isUnlocked, name, subtitle, quotaBytes)

    override suspend fun listMembers(
        accountId: String,
        location: VaultLocation,
        isUnlocked: () -> Boolean,
    ) = repository.listMembers(accountId, location, isUnlocked)

    override suspend fun searchRecipients(
        accountId: String,
        location: VaultLocation,
        query: String,
        isUnlocked: () -> Boolean,
    ) = repository.searchRecipients(accountId, location, query, isUnlocked)

    override suspend fun addMember(
        accountId: String,
        location: VaultLocation,
        recipient: ShareRecipient,
        role: String,
        isUnlocked: () -> Boolean,
    ) = repository.addMember(accountId, location, recipient, role, isUnlocked)

    override suspend fun changeMemberRole(
        accountId: String,
        location: VaultLocation,
        permissionId: String,
        role: String,
        isUnlocked: () -> Boolean,
    ) = repository.changeMemberRole(accountId, location, permissionId, role, isUnlocked)

    override suspend fun removeMember(
        accountId: String,
        location: VaultLocation,
        permissionId: String,
        isUnlocked: () -> Boolean,
    ) = repository.removeMember(accountId, location, permissionId, isUnlocked)
}
