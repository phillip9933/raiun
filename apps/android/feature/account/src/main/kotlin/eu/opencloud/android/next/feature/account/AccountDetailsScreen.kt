package eu.opencloud.android.next.feature.account

import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.ui.ProfileAvatar

@Composable
fun AccountDetailsRoute(
    account: AccountEntity,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    model: AccountDetailsViewModel = viewModel(key = "profile-${account.id}"),
) {
    val state by model.state.collectAsState()
    val picker =
        rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) model.changePhoto(account.id, uri)
        }
    LaunchedEffect(account.id) { model.refresh(account.id) }
    AccountDetailsScreen(
        account,
        state,
        onNavigateBack,
        { picker.launch(arrayOf("image/jpeg", "image/png")) },
        { model.changePhoto(account.id, null) },
        { model.refresh(account.id) },
        modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Explicit screen actions keep platform I/O outside presentation.
fun AccountDetailsScreen(
    account: AccountEntity,
    state: AccountDetailsState,
    onNavigateBack: () -> Unit,
    onUpload: () -> Unit,
    onRemovePhoto: () -> Unit,
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmRemove by rememberSaveable { mutableStateOf(false) }
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.account_information)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.account_back),
                        )
                    }
                },
                actions = {
                    IconButton(onClick = onRefresh, enabled = !state.loading && !state.saving) {
                        Icon(
                            Icons.Default.Refresh,
                            contentDescription = stringResource(R.string.account_refresh_accessibility),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.padding(padding).verticalScroll(rememberScrollState())) {
            if (state.loading || state.saving) LinearProgressIndicator(Modifier.fillMaxWidth())
            Column(
                Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingXl),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                ProfileAvatar(
                    account.id,
                    Modifier.size(OpenCloudDimensions.ProfilePictureSize),
                    state.profile?.displayName ?: account.displayName,
                )
                Text(stringResource(R.string.account_profile_picture), style = MaterialTheme.typography.titleMedium)
                Text(
                    stringResource(R.string.account_profile_picture_formats),
                    style = MaterialTheme.typography.bodySmall,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
                    OutlinedButton(onClick = onUpload, enabled = !state.saving) {
                        Text(stringResource(R.string.account_upload_picture))
                    }
                    TextButton(onClick = { confirmRemove = true }, enabled = !state.saving) {
                        Text(stringResource(R.string.account_remove))
                    }
                }
            }
            state.error?.let {
                Text(
                    it,
                    Modifier.padding(OpenCloudDimensions.SpacingMd),
                    color = MaterialTheme.colorScheme.error,
                )
            }
            AccountFields(account, state.profile)
        }
    }
    if (confirmRemove) {
        AlertDialog(
            onDismissRequest = { confirmRemove = false },
            title = { Text(stringResource(R.string.account_remove_picture_title)) },
            text = { Text(stringResource(R.string.account_remove_picture_confirmation)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmRemove = false
                    onRemovePhoto()
                }) { Text(stringResource(R.string.account_remove)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmRemove = false }) { Text(stringResource(R.string.account_cancel)) }
            },
        )
    }
}

@Composable
private fun AccountDetailRow(
    label: String,
    value: String,
) {
    Column {
        HorizontalDivider(Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd))
        ListItem(
            headlineContent = { Text(label, style = MaterialTheme.typography.labelMedium) },
            supportingContent = { Text(value, style = MaterialTheme.typography.bodyLarge) },
        )
    }
}

@Composable
private fun AccountFields(
    account: AccountEntity,
    profile: eu.opencloud.android.next.core.network.ServerAccountProfile?,
) {
    Column {
        AccountDetailRow(stringResource(R.string.account_username), profile?.username ?: account.userId)
        AccountDetailRow(stringResource(R.string.account_first_last_name), profile?.displayName ?: account.displayName)
        val email =
            profile?.email
                ?: if (profile == null) {
                    stringResource(R.string.account_not_loaded)
                } else {
                    stringResource(R.string.account_no_email)
                }
        AccountDetailRow(stringResource(R.string.account_email), email)
        val context = LocalContext.current
        val used = profile?.usedBytes?.let { Formatter.formatShortFileSize(context, it) }
        val total = profile?.totalBytes?.let { Formatter.formatShortFileSize(context, it) }
        val storage =
            when {
                used == null -> stringResource(R.string.account_storage_not_available)
                total == null -> stringResource(R.string.account_storage_used, used)
                else -> stringResource(R.string.account_storage_used_of_total, used, total)
            }
        AccountDetailRow(stringResource(R.string.account_personal_storage), storage)
        val groups = profile?.groups?.joinToString(", ")
        val groupMemberships =
            when {
                profile == null || groups == null -> stringResource(R.string.account_not_loaded)
                groups.isBlank() -> stringResource(R.string.account_no_group_memberships)
                else -> groups
            }
        AccountDetailRow(stringResource(R.string.account_group_memberships), groupMemberships)
        AccountDetailRow(stringResource(R.string.account_server), account.serverUrl)
    }
}
