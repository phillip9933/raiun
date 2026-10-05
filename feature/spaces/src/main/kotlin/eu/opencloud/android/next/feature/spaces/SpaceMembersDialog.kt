package eu.opencloud.android.next.feature.spaces

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.SpaceMember
import eu.opencloud.android.next.core.network.SpaceMembers
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.ShareManager
import eu.opencloud.android.next.core.sync.SpaceMembersRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
// Account-bound UI actions and safe failures; cancellation propagates.
@Suppress("TooGenericExceptionCaught", "LongMethod")
internal fun SpaceMembersDialog(space: SpaceEntity, onClose: () -> Unit) {
    val context = LocalContext.current
    val owner = rememberCoroutineScope()
    val repository = remember(context) { SpaceMembersRepository(context) }
    var data by remember(space.driveId) { mutableStateOf(SpaceMembers(emptyList(), emptyList())) }
    var busy by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var selected by remember { mutableStateOf<SpaceMember?>(null) }
    var adding by remember { mutableStateOf(false) }
    var removing by remember { mutableStateOf(false) }
    var query by remember { mutableStateOf("") }
    var results by remember { mutableStateOf(emptyList<ShareRecipient>()) }
    var recipient by remember { mutableStateOf<ShareRecipient?>(null) }
    var role by remember { mutableStateOf<String?>(null) }
    val perform: (suspend () -> Unit) -> Unit = { action ->
        busy = true
        error = null
        owner.launch {
            try {
                data =
                    withContext(Dispatchers.IO) {
                        action()
                        repository.list(space.accountId, space.driveId)
                    }
                selected = null
                adding = false
                removing = false
            } catch (
                cancelled: CancellationException,
            ) {
                throw cancelled
            } catch (
                failure: Exception,
            ) {
                error = failure.toOpenCloudError().safeMessage(context)
            } finally {
                busy = false
            }
        }
    }
    val search: () -> Unit = {
        busy = true
        owner.launch {
            try {
                results =
                    withContext(Dispatchers.IO) {
                        ShareManager(context)
                            .searchRecipients(space.accountId, query)
                            .filter { it.type.value in setOf(0, 1) }
                    }
            } catch (
                cancelled: CancellationException,
            ) {
                throw cancelled
            } catch (
                failure: Exception,
            ) {
                error = failure.toOpenCloudError().safeMessage(context)
            } finally {
                busy = false
            }
        }
    }
    LaunchedEffect(space.driveId) { perform {} }
    AlertDialog(onDismissRequest = { if (!busy) onClose() }, title = {
        Text(stringResource(R.string.spaces_members))
    }, text = {
        Column(
            Modifier.verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            Text(space.name)
            MemberStatus(busy, error)
            if (removing) {
                Text(stringResource(R.string.spaces_member_remove_confirmation, selected?.name.orEmpty()))
            } else if (adding || selected != null) {
                selected?.let { Text(it.name) }
                if (adding) {
                    OutlinedTextField(
                        query,
                        {
                            query = it
                            recipient = null
                            results = emptyList()
                        },
                        label = { Text(stringResource(R.string.spaces_member_search)) },
                        enabled = !busy,
                    )
                    FilledTonalButton(enabled = !busy && query.trim().length >= 2, onClick = {
                        search()
                    }) { Text(stringResource(R.string.spaces_member_search)) }
                    RecipientChoices(results, recipient, busy) { recipient = it }
                }
                MemberRoleChoices(data, role, busy) { role = it }
                MemberRemoveAction(selected, busy) { removing = true }
            } else {
                SpaceMemberList(data, busy, onSelect = { member ->
                    selected = member
                    role = member.roles.firstOrNull()
                }, onAdd = {
                    adding = true
                    recipient = null
                    role = null
                })
                OutlinedButton(
                    enabled = !busy,
                    onClick = { perform {} },
                ) { Text(stringResource(R.string.spaces_refresh)) }
            }
        }
    }, confirmButton = {
        MemberSaveButton(
            adding || selected != null,
            busy,
            removing,
            canSaveMember(busy, removing, role, adding, recipient),
            onClose = onClose,
            onSave = {
                val member = selected
                perform { commitMember(repository, space, member, recipient, role, removing, adding) }
            },
        )
    }, dismissButton = {
        MemberCancelButton(adding || selected != null, busy) {
            selected = null
            adding = false
            removing = false
            error = null
        }
    })
}

@Composable
private fun SpaceMemberList(
    data: SpaceMembers,
    busy: Boolean,
    onSelect: (SpaceMember) -> Unit,
    onAdd: () -> Unit,
) {
    val unknownRole = stringResource(R.string.spaces_custom_role)
    Column {
        Text(stringResource(R.string.spaces_members_scope))
        data.members.forEach { member ->
            ListItem(
                headlineContent = { Text(member.name) },
                supportingContent = {
                    Text(
                        member.roles.joinToString { id ->
                            data.roles.firstOrNull { it.id == id }?.name ?: unknownRole
                        },
                    )
                },
                modifier = Modifier.clickable(enabled = !busy) { onSelect(member) },
            )
        }
        if (data.roles.isNotEmpty()) {
            FilledTonalButton(enabled = !busy, onClick = onAdd) { Text(stringResource(R.string.spaces_member_add)) }
        }
    }
}

@Composable
private fun RecipientChoices(
    results: List<ShareRecipient>,
    selected: ShareRecipient?,
    busy: Boolean,
    onSelect: (ShareRecipient) -> Unit,
) {
    Column {
        results.forEach { item ->
            FilterChip(selected == item, { onSelect(item) }, { Text(item.label) }, enabled = !busy)
        }
    }
}

@Composable
private fun MemberRoleChoices(
    data: SpaceMembers,
    role: String?,
    busy: Boolean,
    onSelect: (String) -> Unit,
) {
    FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        data.roles.forEach { item ->
            FilterChip(role == item.id, { onSelect(item.id) }, { Text(item.name) }, enabled = !busy)
        }
    }
}

@Composable
private fun MemberRemoveAction(
    member: SpaceMember?,
    busy: Boolean,
    onRemove: () -> Unit,
) {
    if (member != null) {
        OutlinedButton(enabled = !busy, onClick = onRemove) { Text(stringResource(R.string.spaces_member_remove)) }
    }
}

private fun canSaveMember(
    busy: Boolean,
    removing: Boolean,
    role: String?,
    adding: Boolean,
    recipient: ShareRecipient?,
): Boolean {
    val destinationReady = !adding || recipient != null
    return !busy && (removing || (role != null && destinationReady))
}

@Suppress("LongParameterList") // Explicit selected membership and add/remove editor state.
private suspend fun commitMember(
    repository: SpaceMembersRepository,
    space: SpaceEntity,
    member: SpaceMember?,
    recipient: ShareRecipient?,
    role: String?,
    removing: Boolean,
    adding: Boolean,
) {
    when {
        removing -> repository.remove(space.accountId, space.driveId, requireNotNull(member).id)
        adding -> repository.add(space.accountId, space.driveId, requireNotNull(recipient), requireNotNull(role))
        else -> repository.update(space.accountId, space.driveId, requireNotNull(member).id, requireNotNull(role))
    }
}

@Composable
@Suppress("LongParameterList") // Save/close controls reflect the selected membership editor state.
private fun MemberSaveButton(
    editing: Boolean,
    busy: Boolean,
    removing: Boolean,
    canSave: Boolean,
    onClose: () -> Unit,
    onSave: () -> Unit,
) {
    if (editing) {
        Button(enabled = canSave, onClick = onSave) {
            Text(stringResource(if (removing) R.string.spaces_member_remove else R.string.spaces_save))
        }
    } else {
        TextButton(enabled = !busy, onClick = onClose) { Text(stringResource(R.string.spaces_close)) }
    }
}

@Composable
private fun MemberCancelButton(
    editing: Boolean,
    busy: Boolean,
    onCancel: () -> Unit,
) {
    if (editing) {
        TextButton(enabled = !busy, onClick = onCancel) { Text(stringResource(R.string.spaces_cancel)) }
    }
}

@Composable
private fun MemberStatus(
    busy: Boolean,
    error: String?,
) {
    Column {
        if (busy) LinearProgressIndicator()
        error?.let { Text(it) }
    }
}
