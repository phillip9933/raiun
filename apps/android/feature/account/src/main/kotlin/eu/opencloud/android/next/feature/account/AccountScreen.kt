package eu.opencloud.android.next.feature.account

import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.IconButtonDefaults
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.observePendingAccountRemovalCount
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class AccountUiState(
    val accounts: List<AccountEntity> = emptyList(),
    val activeAccountId: String? = null,
    val busy: Boolean = false,
    val pendingRemovals: Int = 0,
    val error: String? = null,
)

class AccountViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val settings = SettingsRepository.create(application)
    private val mutableState = MutableStateFlow(AccountUiState())
    val state = mutableState.asStateFlow()

    init {
        viewModelScope.launch {
            store.observePendingAccountRemovalCount().collectLatest { count ->
                mutableState.value = mutableState.value.copy(pendingRemovals = count)
            }
        }
        viewModelScope.launch {
            store.observeAccounts().collectLatest { accounts ->
                mutableState.value =
                    mutableState.value.copy(accounts = accounts)
            }
        }
        viewModelScope.launch {
            settings.settings.collectLatest { value ->
                mutableState.value =
                    mutableState.value.copy(activeAccountId = value.activeAccountId)
            }
        }
    }

    fun select(
        accountId: String,
        onSelected: (String) -> Unit,
    ) {
        viewModelScope.launch {
            settings.setActiveAccountId(accountId)
            onSelected(accountId)
        }
    }

    fun remove(
        account: AccountEntity,
        onRemoved: (String?) -> Unit,
    ) {
        viewModelScope.launch {
            mutableState.value = mutableState.value.copy(busy = true, error = null)
            runCatching {
                withContext(Dispatchers.IO) {
                    eu.opencloud.android.next.core.sync
                        .AccountRemovalCoordinator(getApplication())
                        .request(account.id)
                }
            }.onSuccess { next ->
                mutableState.value = mutableState.value.copy(busy = false)
                onRemoved(next)
            }.onFailure {
                if (it is CancellationException) throw it
                mutableState.value =
                    mutableState.value.copy(
                        busy = false,
                        error = it.toOpenCloudError().safeMessage(getApplication<Application>()),
                    )
            }
        }
    }

    fun retryRemoval() {
        viewModelScope.launch {
            mutableState.value = mutableState.value.copy(busy = true, error = null)
            runCatching {
                withContext(Dispatchers.IO) {
                    eu.opencloud.android.next.core.sync
                        .AccountRemovalCoordinator(getApplication())
                        .reconcile()
                }
            }.onFailure {
                if (it is CancellationException) throw it
                mutableState.value =
                    mutableState.value.copy(
                        error = it.toOpenCloudError().safeMessage(getApplication<Application>()),
                    )
            }
            mutableState.value = mutableState.value.copy(busy = false)
        }
    }

    fun dismissError() {
        mutableState.value = mutableState.value.copy(error = null)
    }
}

@Composable
@Suppress("LongParameterList")
fun AccountRoute(
    activeAccountId: String,
    onNavigateBack: () -> Unit,
    onAccountSelect: (String) -> Unit,
    onAccountRemove: (String?) -> Unit,
    onAddAccount: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AccountViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    var detailsId by androidx.compose.runtime.saveable
        .rememberSaveable { mutableStateOf<String?>(null) }
    val detailsAccount = state.accounts.firstOrNull { it.id == detailsId }
    if (detailsAccount != null) {
        androidx.activity.compose.BackHandler { detailsId = null }
        AccountDetailsRoute(detailsAccount, onNavigateBack = { detailsId = null }, modifier = modifier)
        return
    }
    AccountScreen(
        state = state.copy(activeAccountId = state.activeAccountId ?: activeAccountId),
        onNavigateBack = onNavigateBack,
        onSelect = { viewModel.select(it, onAccountSelect) },
        onRemove = { viewModel.remove(it, onAccountRemove) },
        onAddAccount = onAddAccount,
        onDismissError = viewModel::dismissError,
        onRetryRemoval = viewModel::retryRemoval,
        onDetails = { detailsId = it },
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList")
fun AccountScreen(
    state: AccountUiState,
    onNavigateBack: () -> Unit,
    onSelect: (String) -> Unit,
    onRemove: (AccountEntity) -> Unit,
    onAddAccount: () -> Unit,
    onDismissError: () -> Unit,
    modifier: Modifier = Modifier,
    onDetails: (String) -> Unit = {},
    onRetryRemoval: () -> Unit = {},
) {
    var confirmRemove by remember { mutableStateOf<AccountEntity?>(null) }
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(title = {
                Text(stringResource(R.string.account_title_accounts))
            }, navigationIcon = {
                IconButton(
                    onClick = onNavigateBack,
                ) {
                    Icon(
                        Icons.AutoMirrored.Filled.ArrowBack,
                        contentDescription = stringResource(R.string.account_back),
                    )
                }
            })
        },
    ) { padding ->
        if (state.accounts.isEmpty() && state.pendingRemovals == 0) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text(stringResource(R.string.account_empty))
            }
        } else {
            LazyColumn(contentPadding = padding) {
                if (state.pendingRemovals > 0) {
                    item {
                        ListItem(
                            headlineContent = {
                                Text(stringResource(R.string.account_removal_pending, state.pendingRemovals))
                            },
                            supportingContent = {
                                Text(stringResource(R.string.account_removal_pending_help))
                            },
                            trailingContent = {
                                TextButton(onClick = onRetryRemoval, enabled = !state.busy) {
                                    Text(stringResource(R.string.account_removal_retry))
                                }
                            },
                        )
                    }
                }
                item {
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.account_add)) },
                        supportingContent = { Text(stringResource(R.string.account_sign_in_another_server)) },
                        leadingContent = { Icon(Icons.Default.Add, contentDescription = null) },
                        modifier = Modifier.clickable(onClick = onAddAccount),
                    )
                }
                items(state.accounts, key = AccountEntity::id) { account ->
                    AccountRow(
                        account = account,
                        state = state,
                        onDetails = onDetails,
                        onSelect = onSelect,
                        onRemove = { confirmRemove = it },
                    )
                }
            }
        }
    }
    confirmRemove?.let { account ->
        AlertDialog(
            onDismissRequest = { confirmRemove = null },
            title = { Text(stringResource(R.string.account_remove_title)) },
            text = {
                Text(stringResource(R.string.account_remove_confirmation, account.displayName))
            },
            confirmButton = {
                TextButton(
                    colors =
                        ButtonDefaults.textButtonColors(
                            contentColor = MaterialTheme.colorScheme.error,
                        ),
                    onClick = {
                        confirmRemove = null
                        onRemove(account)
                    },
                ) { Text(stringResource(R.string.account_remove)) }
            },
            dismissButton = {
                TextButton(onClick = { confirmRemove = null }) { Text(stringResource(R.string.account_cancel)) }
            },
        )
    }
    state.error?.let {
        AlertDialog(onDismissRequest = onDismissError, title = {
            Text(stringResource(R.string.account_title_accounts))
        }, text = { Text(it) }, confirmButton = {
            TextButton(onClick = onDismissError) { Text(stringResource(R.string.account_ok)) }
        })
    }
}

@Composable
private fun AccountRow(
    account: AccountEntity,
    state: AccountUiState,
    onDetails: (String) -> Unit,
    onSelect: (String) -> Unit,
    onRemove: (AccountEntity) -> Unit,
) {
    val isSelected = state.activeAccountId == account.id
    val accent =
        eu.opencloud.android.next.core.ui
            .accountAccent(account.id)
    val selectedContainer =
        eu.opencloud.android.next.core.ui
            .accountAccentContainer(account.id)
    val content = MaterialTheme.colorScheme.onSurface
    val supporting = MaterialTheme.colorScheme.onSurfaceVariant
    ListItem(
        modifier =
            Modifier
                .padding(
                    horizontal = OpenCloudDimensions.SpacingMd,
                    vertical = OpenCloudDimensions.SpacingXxs,
                ).clip(RoundedCornerShape(OpenCloudDimensions.ContentCornerRadius))
                .semantics { selected = isSelected }
                .clickable { onDetails(account.id) },
        colors =
            ListItemDefaults.colors(
                containerColor = if (isSelected) selectedContainer else MaterialTheme.colorScheme.surface,
                headlineColor = content,
                supportingColor = supporting,
                leadingIconColor = supporting,
                trailingIconColor = supporting,
            ),
        headlineContent = { Text(account.displayName) },
        supportingContent = {
            Column {
                Text(account.userId, maxLines = 1, overflow = TextOverflow.Ellipsis)
                Text(
                    eu.opencloud.android.next.core.ui
                        .accountServerLabel(account.serverUrl),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        },
        leadingContent = {
            eu.opencloud.android.next.core.ui.ProfileAvatar(
                account.id,
                name = account.displayName,
            )
        },
        trailingContent = {
            androidx.compose.foundation.layout.Row {
                RadioButton(
                    selected = isSelected,
                    onClick = { onSelect(account.id) },
                    colors =
                        RadioButtonDefaults.colors(
                            selectedColor = accent,
                            unselectedColor = MaterialTheme.colorScheme.outline,
                        ),
                )
                IconButton(
                    onClick = {
                        onRemove(account)
                    },
                    enabled = !state.busy,
                    colors =
                        IconButtonDefaults.iconButtonColors(
                            contentColor = MaterialTheme.colorScheme.error,
                        ),
                ) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription =
                            stringResource(
                                R.string.account_remove_accessibility,
                                account.displayName,
                            ),
                    )
                }
            }
        },
    )
}
