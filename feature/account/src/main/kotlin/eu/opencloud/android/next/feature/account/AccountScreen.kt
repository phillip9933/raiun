package eu.opencloud.android.next.feature.account

import android.app.Application
import android.provider.DocumentsContract
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
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
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.VaultKeyStore
import eu.opencloud.android.next.core.security.VaultPreferences
import eu.opencloud.android.next.core.sync.TransferManager
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
    val error: String? = null,
)

class AccountViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val settings = SettingsRepository.create(application)
    private val transfers = TransferManager(application, store)
    private val mutableState = MutableStateFlow(AccountUiState())
    val state = mutableState.asStateFlow()

    init {
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
                    transfers.cancelAccountWork(account.id)
                    eu.opencloud.android.next.core.security.AccountSessions
                        .get(getApplication())
                        .remove(account.id)
                    VaultKeyStore(getApplication()).forgetAccount(account.id)
                    VaultPreferences(getApplication()).forgetAccount(account.id)
                    eu.opencloud.android.next.core.sync
                        .VaultOfflineStore(getApplication())
                        .forgetAccount(account.id)
                    store.removeAccount(account.id)
                    eu.opencloud.android.next.core.sync
                        .clearAccountPrivateFiles(getApplication(), account.id)
                    eu.opencloud.android.next.core.sync.AccountProfiles
                        .clear(getApplication(), account.id)
                    val next = store.activeAccounts().firstOrNull()?.id
                    settings.setActiveAccountId(next)
                    getApplication<Application>().contentResolver.notifyChange(
                        DocumentsContract.buildRootsUri("${getApplication<Application>().packageName}.documents"),
                        null,
                    )
                    next
                }
            }.onSuccess { next ->
                mutableState.value = mutableState.value.copy(busy = false)
                onRemoved(next)
            }.onFailure {
                mutableState.value =
                    mutableState.value.copy(
                        busy = false,
                        error = it.toOpenCloudError().safeMessage(getApplication<Application>()),
                    )
            }
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
    val state by viewModel.state.collectAsState()
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
        if (state.accounts.isEmpty()) {
            Box(Modifier.fillMaxSize().padding(padding), contentAlignment = Alignment.Center) {
                Text(stringResource(R.string.account_empty))
            }
        } else {
            LazyColumn(contentPadding = padding) {
                item {
                    ListItem(
                        headlineContent = { Text(stringResource(R.string.account_add)) },
                        supportingContent = { Text(stringResource(R.string.account_sign_in_another_server)) },
                        leadingContent = { Icon(Icons.Default.Add, contentDescription = null) },
                        modifier = Modifier.clickable(onClick = onAddAccount),
                    )
                }
                items(state.accounts, key = AccountEntity::id) { account ->
                    ListItem(
                        modifier = Modifier.clickable { onDetails(account.id) },
                        headlineContent = { Text(account.displayName) },
                        supportingContent = { Text("${account.userId} • ${account.serverUrl}") },
                        leadingContent = {
                            eu.opencloud.android.next.core.ui.ProfileAvatar(
                                account.id,
                                name = account.displayName,
                            )
                        },
                        trailingContent = {
                            androidx.compose.foundation.layout.Row {
                                RadioButton(
                                    selected = state.activeAccountId == account.id,
                                    onClick = { onSelect(account.id) },
                                )
                                IconButton(onClick = {
                                    confirmRemove = account
                                }, enabled = !state.busy) {
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
                TextButton(onClick = {
                    confirmRemove = null
                    onRemove(account)
                }) { Text(stringResource(R.string.account_remove)) }
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
