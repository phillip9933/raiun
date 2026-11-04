package eu.opencloud.android.next.feature.shares

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.GraphShareTarget
import eu.opencloud.android.next.core.network.GuestPermission
import eu.opencloud.android.next.core.network.GuestRole
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.GuestInvitationManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("TooGenericExceptionCaught") // UI boundary maps failures to safe messages and rethrows cancellation.
internal fun GuestInvitationsScreen(
    accountId: String,
    resource: ResourceEntity,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    actions: GuestInvitationActions? = null,
) {
    val context = LocalContext.current
    val owner = rememberCoroutineScope()
    val guestActions =
        remember(context, actions) {
            actions ?: AndroidGuestInvitationActions(context.applicationContext)
        }
    val target =
        remember(accountId, resource.accountId, resource.spaceId, resource.remoteId) {
            guestInvitationTarget(accountId, resource)
        }
    var guests by remember(
        accountId,
        resource.spaceId,
        resource.remoteId,
    ) { mutableStateOf(emptyList<GuestPermission>()) }
    var roles by remember(accountId, resource.spaceId, resource.remoteId) { mutableStateOf(emptyList<GuestRole>()) }
    var loading by remember(accountId, resource.spaceId, resource.remoteId) { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var message by remember { mutableStateOf<String?>(null) }
    var dialogState by remember { mutableStateOf(GuestDialogState()) }

    suspend fun refreshGuests() {
        val item = requireNotNull(target) { "This item cannot be shared with guests." }
        val listing = withContext(Dispatchers.IO) { guestActions.list(accountId, item) }
        guests = listing.guests
        roles = listing.roles
    }

    suspend fun perform(
        successMessage: String,
        action: suspend () -> Unit,
    ) {
        busy = true
        error = null
        message = null
        try {
            withContext(Dispatchers.IO) { action() }
            message = successMessage
            refreshGuests()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            error = guestErrorMessage(failure, context)
        } finally {
            busy = false
        }
    }

    LaunchedEffect(accountId, resource.spaceId, resource.remoteId) {
        if (target == null) {
            error = context.getString(R.string.guest_item_unavailable)
            loading = false
        } else {
            loading = true
            error = null
            try {
                refreshGuests()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                error = guestErrorMessage(failure, context)
            } finally {
                loading = false
            }
        }
    }

    val refreshAction: () -> Unit = {
        owner.launch {
            loading = true
            error = null
            try {
                refreshGuests()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                error = guestErrorMessage(failure, context)
            } finally {
                loading = false
            }
        }
        Unit
    }
    Scaffold(
        modifier = modifier,
        topBar = { GuestInvitationTopBar(resource.name, busy, loading, onNavigateBack, refreshAction) },
    ) { padding ->
        GuestInvitationContent(
            modifier = Modifier.fillMaxSize().padding(padding),
            state = GuestContentState(guests, roles, loading, busy, error, message, target != null),
            actions =
                GuestContentActions(
                    onInvite = { dialogState = dialogState.copy(showInviteEditor = true) },
                    onEdit = { guest -> dialogState = dialogState.copy(editGuest = guest) },
                    onRevoke = { guest -> dialogState = dialogState.copy(revokeGuest = guest) },
                ),
        )
    }
    GuestInvitationDialogs(
        state = dialogState,
        roles = roles,
        busy = busy,
        actions =
            GuestDialogActions(
                onState = { dialogState = it },
                onSendInvite = { invite ->
                    dialogState = dialogState.copy(pendingInvite = null)
                    target?.let { item ->
                        owner.launch {
                            perform(context.getString(R.string.guest_invited)) {
                                guestActions.invite(
                                    accountId,
                                    item,
                                    invite.email,
                                    invite.roleId,
                                    invite.expirationDateTime,
                                )
                            }
                        }
                    }
                },
                onUpdateGuest = { guest, roleId, expiration ->
                    dialogState = dialogState.copy(editGuest = null)
                    target?.let { item ->
                        owner.launch {
                            perform(context.getString(R.string.guest_updated)) {
                                guestActions.update(accountId, item, guest.id, roleId, expiration)
                            }
                        }
                    }
                },
                onRemoveGuest = { guest ->
                    dialogState = dialogState.copy(revokeGuest = null)
                    target?.let { item ->
                        owner.launch {
                            perform(context.getString(R.string.guest_removed)) {
                                guestActions.remove(accountId, item, guest.id)
                            }
                        }
                    }
                },
            ),
    )
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
private fun GuestInvitationTopBar(
    resourceName: String,
    busy: Boolean,
    loading: Boolean,
    onNavigateBack: () -> Unit,
    onRefresh: () -> Unit,
) {
    TopAppBar(
        title = { Text(stringResource(R.string.guest_title, resourceName)) },
        navigationIcon = {
            IconButton(onClick = onNavigateBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.guest_back))
            }
        },
        actions = {
            IconButton(enabled = !busy && !loading, onClick = onRefresh) {
                Icon(Icons.Default.Refresh, stringResource(R.string.shares_refresh))
            }
        },
    )
}

@Composable
private fun GuestInvitationContent(
    state: GuestContentState,
    actions: GuestContentActions,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier.padding(horizontal = OpenCloudDimensions.SpacingMd),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
    ) {
        Button(
            enabled = !state.busy && !state.loading && state.targetAvailable && state.roles.isNotEmpty(),
            onClick = actions.onInvite,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(stringResource(R.string.guest_invite_button))
        }
        Text(stringResource(R.string.guest_server_policy_note), color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (state.roles.isEmpty() && !state.loading && state.error == null) {
            Text(stringResource(R.string.guest_role_unavailable), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        state.message?.let { Text(it, color = MaterialTheme.colorScheme.primary) }
        if (state.loading) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator()
            }
            Text(stringResource(R.string.guest_loading))
        } else if (state.guests.isEmpty() && state.error == null) {
            Text(stringResource(R.string.guest_empty), color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            LazyColumn(
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(bottom = OpenCloudDimensions.SpacingXl),
            ) {
                items(state.guests, key = GuestPermission::id) { guest ->
                    GuestPermissionRow(
                        guest = guest,
                        roles = state.roles,
                        enabled = !state.busy,
                        onEdit = { actions.onEdit(guest) },
                        onRemove = { actions.onRevoke(guest) },
                    )
                }
            }
        }
        if (state.busy) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                CircularProgressIndicator()
            }
        }
    }
}

private data class GuestContentState(
    val guests: List<GuestPermission>,
    val roles: List<GuestRole>,
    val loading: Boolean,
    val busy: Boolean,
    val error: String?,
    val message: String?,
    val targetAvailable: Boolean,
)

private data class GuestContentActions(
    val onInvite: () -> Unit,
    val onEdit: (GuestPermission) -> Unit,
    val onRevoke: (GuestPermission) -> Unit,
)

private data class GuestDialogState(
    val showInviteEditor: Boolean = false,
    val editGuest: GuestPermission? = null,
    val pendingInvite: PendingGuestInvite? = null,
    val revokeGuest: GuestPermission? = null,
)

private data class GuestDialogActions(
    val onState: (GuestDialogState) -> Unit,
    val onSendInvite: (PendingGuestInvite) -> Unit,
    val onUpdateGuest: (GuestPermission, String, String?) -> Unit,
    val onRemoveGuest: (GuestPermission) -> Unit,
)

@Composable
private fun GuestInvitationDialogs(
    state: GuestDialogState,
    roles: List<GuestRole>,
    busy: Boolean,
    actions: GuestDialogActions,
) {
    if (state.showInviteEditor) {
        GuestEditorDialog(
            config =
                GuestEditorConfig(
                    title = stringResource(R.string.guest_invite_button),
                    roles = roles,
                    initialRole = null,
                    allowEmail = true,
                    busy = busy,
                ),
            onDismiss = { if (!busy) actions.onState(state.copy(showInviteEditor = false)) },
            onSubmit = { email, roleId, expiration ->
                actions.onState(
                    state.copy(
                        showInviteEditor = false,
                        pendingInvite = PendingGuestInvite(email, roleId, expiration),
                    ),
                )
            },
        )
    }
    state.editGuest?.let { guest ->
        GuestEditorDialog(
            config =
                GuestEditorConfig(
                    title = stringResource(R.string.guest_edit_title),
                    roles = roles,
                    initialRole = guest.roles.firstOrNull(),
                    initialExpiration = guest.expirationDateTime?.let(::parseExpirationMillis),
                    allowEmail = false,
                    busy = busy,
                ),
            onDismiss = { if (!busy) actions.onState(state.copy(editGuest = null)) },
            onSubmit = { _, roleId, expiration -> actions.onUpdateGuest(guest, roleId, expiration) },
        )
    }
    state.pendingInvite?.let { invite ->
        GuestInviteConfirmationDialog(invite, roles, busy, {
            if (!busy) actions.onState(state.copy(pendingInvite = null))
        }) { actions.onSendInvite(invite) }
    }
    state.revokeGuest?.let { guest ->
        GuestRevokeConfirmationDialog(guest, busy, {
            if (!busy) actions.onState(state.copy(revokeGuest = null))
        }) { actions.onRemoveGuest(guest) }
    }
}

@Composable
private fun GuestInviteConfirmationDialog(
    invite: PendingGuestInvite,
    roles: List<GuestRole>,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    val context = LocalContext.current
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.guest_send_confirmation_title)) },
        text = {
            Text(
                stringResource(R.string.guest_send_confirmation, invite.email) + "\n" +
                    invitationSummary(invite, roles, context),
            )
        },
        confirmButton = {
            TextButton(enabled = !busy, onClick = onConfirm) { Text(stringResource(R.string.guest_send_email)) }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) { Text(stringResource(R.string.guest_cancel)) }
        },
    )
}

@Composable
private fun GuestRevokeConfirmationDialog(
    guest: GuestPermission,
    busy: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.guest_revoke_confirmation_title)) },
        text = { Text(stringResource(R.string.guest_revoke_confirmation, guest.email)) },
        confirmButton = {
            TextButton(enabled = !busy, onClick = onConfirm) {
                Text(stringResource(R.string.guest_revoke), color = MaterialTheme.colorScheme.error)
            }
        },
        dismissButton = {
            TextButton(enabled = !busy, onClick = onDismiss) { Text(stringResource(R.string.guest_cancel)) }
        },
    )
}

@Composable
private fun GuestPermissionRow(
    guest: GuestPermission,
    roles: List<GuestRole>,
    enabled: Boolean,
    onEdit: () -> Unit,
    onRemove: () -> Unit,
) {
    val roleNames = guest.roles.map { id -> roles.firstOrNull { it.id == id }?.name ?: id }
    ListItem(
        headlineContent = { Text(guest.email) },
        supportingContent = {
            Column {
                Text(roleNames.joinToString().ifBlank { stringResource(R.string.guest_role_unavailable) })
                val expiry = guest.expirationDateTime?.let(::formatExpiration)
                Text(
                    expiry?.let { stringResource(R.string.guest_expiry_summary, it) }
                        ?: stringResource(R.string.guest_no_expiration),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        trailingContent = {
            Row {
                IconButton(enabled = enabled, onClick = onEdit) {
                    Icon(Icons.Default.Edit, stringResource(R.string.guest_edit_title))
                }
                IconButton(
                    enabled = enabled,
                    onClick = onRemove,
                    colors =
                        androidx.compose.material3.IconButtonDefaults.iconButtonColors(
                            contentColor = MaterialTheme.colorScheme.error,
                        ),
                ) {
                    Icon(
                        Icons.Default.DeleteOutline,
                        stringResource(R.string.guest_revoke),
                    )
                }
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GuestEditorDialog(
    config: GuestEditorConfig,
    onDismiss: () -> Unit,
    onSubmit: (String, String, String?) -> Unit,
) {
    var email by remember { mutableStateOf("") }
    var roleId by rememberSaveable(config.initialRole) { mutableStateOf(config.initialRole.orEmpty()) }
    var expirationMillis by rememberSaveable(config.initialExpiration) { mutableStateOf(config.initialExpiration) }
    var showDatePicker by rememberSaveable { mutableStateOf(false) }
    val datePicker = rememberDatePickerState(initialSelectedDateMillis = expirationMillis)
    val today =
        LocalDate
            .now(ZoneOffset.UTC)
            .atStartOfDay(ZoneOffset.UTC)
            .toInstant()
            .toEpochMilli()
    val emailValid = !config.allowEmail || (email.trim().contains('@') && email.trim().length <= 254)
    val dateValid = expirationMillis == null || expirationMillis!! >= today
    val ready = !config.busy && roleId.isNotBlank() && emailValid && dateValid

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(config.title) },
        text = {
            Column(
                modifier = Modifier.imePadding(),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                if (config.allowEmail) {
                    OutlinedTextField(
                        value = email,
                        onValueChange = { email = it },
                        label = { Text(stringResource(R.string.guest_email_label)) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
                        enabled = !config.busy,
                        singleLine = true,
                    )
                }
                Text(stringResource(R.string.guest_role_label), style = MaterialTheme.typography.titleSmall)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                    config.roles.forEach { role ->
                        FilterChip(
                            selected = role.id == roleId,
                            onClick = { roleId = role.id },
                            label = { Text(role.name) },
                            enabled = !config.busy,
                        )
                    }
                }
                Text(stringResource(R.string.guest_expiration_label), style = MaterialTheme.typography.titleSmall)
                OutlinedButton(enabled = !config.busy, onClick = { showDatePicker = true }) {
                    Text(expirationMillis?.let(::formatExpiration) ?: stringResource(R.string.guest_no_expiration))
                }
                if (expirationMillis != null) {
                    TextButton(enabled = !config.busy, onClick = { expirationMillis = null }) {
                        Text(stringResource(R.string.guest_clear_date))
                    }
                }
            }
        },
        confirmButton = {
            TextButton(enabled = ready, onClick = {
                onSubmit(email.trim(), roleId, expirationMillis?.let(::expirationRequestValue))
            }) {
                Text(stringResource(if (config.allowEmail) R.string.guest_invite_continue else R.string.guest_save))
            }
        },
        dismissButton = {
            TextButton(enabled = !config.busy, onClick = onDismiss) { Text(stringResource(R.string.guest_cancel)) }
        },
    )
    if (showDatePicker) {
        DatePickerDialog(
            onDismissRequest = { showDatePicker = false },
            confirmButton = {
                TextButton(
                    enabled = datePicker.selectedDateMillis?.let { it >= today } == true,
                    onClick = {
                        expirationMillis = datePicker.selectedDateMillis
                        showDatePicker = false
                    },
                ) { Text(stringResource(R.string.share_ok)) }
            },
            dismissButton = {
                TextButton(onClick = { showDatePicker = false }) { Text(stringResource(R.string.guest_cancel)) }
            },
        ) {
            DatePicker(state = datePicker)
        }
    }
}

private data class PendingGuestInvite(
    val email: String,
    val roleId: String,
    val expirationDateTime: String?,
)

private data class GuestEditorConfig(
    val title: String,
    val roles: List<GuestRole>,
    val initialRole: String?,
    val initialExpiration: Long? = null,
    val allowEmail: Boolean,
    val busy: Boolean,
)

internal interface GuestInvitationActions {
    suspend fun list(
        accountId: String,
        target: GraphShareTarget,
    ): eu.opencloud.android.next.core.network.GuestPermissions

    suspend fun invite(
        accountId: String,
        target: GraphShareTarget,
        email: String,
        roleId: String,
        expirationDateTime: String?,
    ): GuestPermission

    suspend fun update(
        accountId: String,
        target: GraphShareTarget,
        permissionId: String,
        roleId: String,
        expirationDateTime: String?,
    ): GuestPermission

    suspend fun remove(
        accountId: String,
        target: GraphShareTarget,
        permissionId: String,
    )
}

private class AndroidGuestInvitationActions(
    context: android.content.Context,
) : GuestInvitationActions {
    private val manager = GuestInvitationManager(context)

    override suspend fun list(
        accountId: String,
        target: GraphShareTarget,
    ) = manager.list(accountId, target)

    override suspend fun invite(
        accountId: String,
        target: GraphShareTarget,
        email: String,
        roleId: String,
        expirationDateTime: String?,
    ) = manager.invite(accountId, target, email, roleId, expirationDateTime)

    override suspend fun update(
        accountId: String,
        target: GraphShareTarget,
        permissionId: String,
        roleId: String,
        expirationDateTime: String?,
    ) = manager.update(accountId, target, permissionId, roleId, expirationDateTime)

    override suspend fun remove(
        accountId: String,
        target: GraphShareTarget,
        permissionId: String,
    ) = manager.remove(accountId, target, permissionId)
}

private fun invitationSummary(
    invite: PendingGuestInvite,
    roles: List<GuestRole>,
    context: android.content.Context,
): String {
    val role = roles.firstOrNull { it.id == invite.roleId }?.name ?: invite.roleId
    val expiry = invite.expirationDateTime?.let(::formatExpiration) ?: context.getString(R.string.guest_no_expiration)
    return "${context.getString(
        R.string.guest_role_label,
    )}: $role\n${context.getString(R.string.guest_expiration_label)}: $expiry"
}

private fun parseExpirationMillis(value: String): Long? =
    runCatching { Instant.parse(value).toEpochMilli() }.getOrNull()

private fun formatExpiration(value: String): String =
    runCatching {
        Instant
            .parse(value)
            .atZone(ZoneOffset.UTC)
            .toLocalDate()
            .toString()
    }.getOrDefault(value)

private fun formatExpiration(value: Long): String =
    Instant
        .ofEpochMilli(value)
        .atZone(ZoneOffset.UTC)
        .toLocalDate()
        .toString()

private fun expirationRequestValue(value: Long): String =
    Instant
        .ofEpochMilli(value)
        .atZone(ZoneOffset.UTC)
        .toLocalDate()
        .atStartOfDay(ZoneOffset.UTC)
        .plusDays(1)
        .minusSeconds(1)
        .toInstant()
        .toString()

private fun guestErrorMessage(
    failure: Throwable,
    context: android.content.Context,
): String =
    when (failure.toOpenCloudError()) {
        OpenCloudError.AccessDenied -> context.getString(R.string.guest_server_denied)
        OpenCloudError.Unsupported -> context.getString(R.string.guest_support_unavailable)
        else -> failure.toOpenCloudError().safeMessage(context)
    }

private fun guestInvitationTarget(
    accountId: String,
    resource: ResourceEntity,
): GraphShareTarget? {
    val ordinaryItem = resource.path.trim('/').isNotBlank()
    val sameAccount = resource.accountId == accountId
    val idsPresent = resource.spaceId.isNotBlank() && resource.remoteId.isNotBlank()
    return if (sameAccount &&
        ordinaryItem &&
        idsPresent
    ) {
        GraphShareTarget(resource.spaceId, resource.remoteId)
    } else {
        null
    }
}
