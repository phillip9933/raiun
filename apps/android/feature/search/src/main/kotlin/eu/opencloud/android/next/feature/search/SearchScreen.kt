package eu.opencloud.android.next.feature.search

import android.app.Application
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.SearchRepository
import eu.opencloud.android.next.core.sync.SearchRepositoryResult
import eu.opencloud.android.next.core.sync.TransferManager
import eu.opencloud.android.next.core.sync.createSearchRepository
import eu.opencloud.android.next.feature.files.ResourceActionSheet
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalCoroutinesApi::class)
class SearchViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val transfers = TransferManager(application, store)
    private val repository: SearchRepository = createSearchRepository(application, store)
    private val query = MutableStateFlow("")
    private val mutableState = MutableStateFlow(SearchUiState())
    val state: StateFlow<SearchUiState> = mutableState.asStateFlow()
    private var accountId: String? = null

    init {
        viewModelScope.launch(Dispatchers.IO) {
            query
                .flatMapLatest { value ->
                    val account = accountId
                    if (account == null || value.isBlank()) {
                        flowOf(SearchRepositoryResult(emptyList(), remoteSupported = false))
                    } else {
                        repository.search(account, value)
                    }
                }.onStart { emit(SearchRepositoryResult(emptyList(), remoteSupported = false)) }
                .collectLatest { result ->
                    mutableState.value =
                        mutableState.value.copy(
                            resources = result.resources,
                            remoteSupported = result.remoteSupported,
                            isRemoteLoading = result.remoteLoading,
                            remoteError = result.remoteError,
                            remoteResultsCapped = result.remoteResultsCapped,
                        )
                }
        }
    }

    fun load(accountId: String) {
        if (this.accountId == accountId) return
        this.accountId = accountId
        query.value = mutableState.value.query
    }

    fun setQuery(value: String) {
        mutableState.value = mutableState.value.copy(query = value, remoteError = null)
        query.value = value
    }

    fun showActions(resource: ResourceEntity?) {
        mutableState.value = mutableState.value.copy(actionResource = resource)
    }

    fun dismissActions() = showActions(null)

    fun downloadForOffline(resource: ResourceEntity) {
        runAction(
            getApplication<Application>().localizedString(R.string.search_offline_queued),
        ) {
            transfers.makeAvailableOffline(resource)
        }
    }

    fun unavailableAction() {
        mutableState.value =
            mutableState.value.copy(
                actionResource = null,
                message =
                    getApplication<Application>().localizedString(R.string.search_open_in_files),
            )
    }

    fun dismissMessage() {
        mutableState.value = mutableState.value.copy(message = null)
    }

    private fun runAction(
        message: String,
        action: suspend () -> Unit,
    ) {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { action() } }
                .onSuccess { mutableState.value = mutableState.value.copy(actionResource = null, message = message) }
                .onFailure {
                    mutableState.value =
                        mutableState.value.copy(
                            message =
                                it.message
                                    ?: getApplication<Application>().localizedString(R.string.search_action_failed),
                        )
                }
        }
    }
}

data class SearchUiState(
    val query: String = "",
    val resources: List<ResourceEntity> = emptyList(),
    val remoteSupported: Boolean = false,
    val isRemoteLoading: Boolean = false,
    val remoteError: String? = null,
    val remoteResultsCapped: Boolean = false,
    val actionResource: ResourceEntity? = null,
    val message: String? = null,
)

@Composable
@Suppress("FunctionNaming", "ktlint:standard:function-naming")
fun SearchRoute(
    accountId: String,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SearchViewModel = viewModel(),
) {
    val state by viewModel.state.collectAsState()
    LaunchedEffect(accountId) { viewModel.load(accountId) }
    SearchScreen(
        state = state,
        onQueryChange = viewModel::setQuery,
        onNavigateBack = onNavigateBack,
        onShowActions = viewModel::showActions,
        onDismissActions = viewModel::dismissActions,
        onDownloadForOffline = viewModel::downloadForOffline,
        onUnavailableAction = viewModel::unavailableAction,
        onDismissMessage = viewModel::dismissMessage,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("FunctionNaming", "ktlint:standard:function-naming", "LongParameterList")
fun SearchScreen(
    state: SearchUiState,
    onQueryChange: (String) -> Unit,
    onNavigateBack: () -> Unit,
    onShowActions: (ResourceEntity?) -> Unit,
    onDismissActions: () -> Unit,
    onDownloadForOffline: (ResourceEntity) -> Unit,
    onUnavailableAction: () -> Unit,
    onDismissMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = {
                    TextField(
                        value = state.query,
                        onValueChange = onQueryChange,
                        modifier = Modifier.fillMaxWidth(),
                        placeholder = { Text(stringResource(R.string.search_placeholder)) },
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                        trailingIcon = {
                            if (state.query.isNotEmpty()) {
                                IconButton(
                                    onClick = { onQueryChange("") },
                                ) { Icon(Icons.Default.Clear, stringResource(R.string.search_clear)) }
                            }
                        },
                        singleLine = true,
                    )
                },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.search_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        SearchContent(state, onShowActions, Modifier.padding(padding))
    }
    state.actionResource?.let { resource ->
        ResourceActionSheet(
            resource = resource,
            onDismiss = onDismissActions,
            onRename = onUnavailableAction,
            onMove = onUnavailableAction,
            onCopy = onUnavailableAction,
            onDownloadForOffline = { onDownloadForOffline(resource) },
            onDelete = onUnavailableAction,
        )
    }
    state.message?.let { message ->
        AlertDialog(
            onDismissRequest = onDismissMessage,
            title = { Text(stringResource(R.string.search_action_title)) },
            text = { Text(message) },
            confirmButton = { TextButton(onClick = onDismissMessage) { Text(stringResource(R.string.search_ok)) } },
        )
    }
}

@Composable
private fun SearchContent(
    state: SearchUiState,
    onShowActions: (ResourceEntity?) -> Unit,
    modifier: Modifier = Modifier,
) {
    when {
        state.query.isBlank() ->
            SearchMessage(
                stringResource(R.string.search_empty_title),
                stringResource(R.string.search_empty_message),
                modifier,
            )
        state.resources.isEmpty() && state.isRemoteLoading ->
            Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }
        state.resources.isEmpty() && state.remoteError != null ->
            SearchMessage(
                stringResource(R.string.search_unavailable_title),
                stringResource(R.string.search_unavailable_message),
                modifier,
                offline = true,
            )
        state.resources.isEmpty() ->
            SearchMessage(
                stringResource(R.string.search_no_results_title),
                stringResource(R.string.search_no_results_message),
                modifier,
            )
        else ->
            LazyColumn(modifier = modifier.fillMaxSize()) {
                item {
                    Text(
                        searchStatus(state),
                        Modifier.padding(OpenCloudDimensions.SpacingMd),
                        style = MaterialTheme.typography.labelLarge,
                    )
                }
                items(state.resources, key = { "${it.spaceId}:${it.remoteId}" }) { resource ->
                    ListItem(
                        headlineContent = { Text(resource.name) },
                        supportingContent = { Text(resource.path) },
                        leadingContent = {
                            Icon(
                                if (resource.kind == ResourceKind.FOLDER) {
                                    Icons.Default.Folder
                                } else {
                                    Icons.AutoMirrored.Filled.InsertDriveFile
                                },
                                contentDescription = null,
                            )
                        },
                        modifier = Modifier.clickable { onShowActions(resource) },
                    )
                }
            }
    }
}

@Composable
private fun searchStatus(state: SearchUiState): String =
    when {
        state.isRemoteLoading -> stringResource(R.string.search_status_loading)
        state.remoteError != null -> stringResource(R.string.search_status_server_error)
        state.remoteSupported && state.remoteResultsCapped -> stringResource(R.string.search_status_capped)
        state.remoteSupported -> stringResource(R.string.search_status_combined)
        else -> stringResource(R.string.search_status_device)
    }

@Composable
private fun SearchMessage(
    title: String,
    message: String,
    modifier: Modifier = Modifier,
    offline: Boolean = false,
) {
    Box(modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(if (offline) Icons.Default.CloudOff else Icons.Default.Search, contentDescription = null)
            Text(title, style = MaterialTheme.typography.titleLarge)
            Text(message)
        }
    }
}
