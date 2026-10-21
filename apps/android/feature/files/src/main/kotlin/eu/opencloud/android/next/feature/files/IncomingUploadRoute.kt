package eu.opencloud.android.next.feature.files

import android.net.Uri
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.IncomingShareStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IncomingUploadRoute(
    batchId: String,
    sources: List<Uri>,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: IncomingUploadViewModel = viewModel(key = batchId),
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    val mediaPermission = rememberOriginalMediaPermission(onCancel = onClose) { viewModel.load(batchId, it) }
    LaunchedEffect(batchId) {
        if (withContext(Dispatchers.IO) { IncomingShareStore(context).isStaged(batchId) }) {
            viewModel.load(batchId, emptyList())
        } else {
            mediaPermission(sources)
        }
    }
    LaunchedEffect(state.complete, onClose) { if (state.complete) onClose() }
    BackHandler { viewModel.discard(onClose) }
    Scaffold(modifier = modifier, topBar = {
        TopAppBar(title = { Text(stringResource(R.string.document_upload_title)) }, navigationIcon = {
            IconButton(onClick = { viewModel.discard(onClose) }) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.document_cancel))
            }
        })
    }) { padding ->
        Column(
            Modifier.fillMaxSize().padding(padding).padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            if (state.busy) {
                CircularProgressIndicator()
                Text(stringResource(R.string.document_preparing_uploads))
            }
            state.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Text(
                pluralStringResource(R.plurals.document_incoming_files, state.sourceCount, state.sourceCount),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(state.files.take(3).joinToString { it.name }, maxLines = 3)
            if (!state.busy && state.files.isEmpty() && state.sourceCount > 0) {
                Text(stringResource(R.string.document_shared_copy_on_upload))
            }
            if (!state.busy &&
                state.accounts.isEmpty()
            ) {
                Text(stringResource(R.string.document_sign_in_to_share))
            }
            IncomingDestinationChoices(
                state,
                viewModel::selectAccount,
                viewModel::selectSpace,
                viewModel::openFolder,
                viewModel::up,
            )
            Button(
                onClick = viewModel::upload,
                enabled =
                    !state.busy && state.spaceId != null && state.sourceCount > 0,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    if (state.destinationLocked) {
                        stringResource(
                            R.string.document_retry_uploads,
                        )
                    } else {
                        stringResource(R.string.document_upload_here)
                    },
                )
            }
        }
    }
}

@Composable
private fun androidx.compose.foundation.layout.ColumnScope.IncomingDestinationChoices(
    state: IncomingUploadState,
    onAccount: (String) -> Unit,
    onSpace: (String) -> Unit,
    onFolder: (eu.opencloud.android.next.core.database.ResourceEntity) -> Unit,
    onUp: () -> Unit,
) {
    val enabled = !state.busy && !state.destinationLocked
    LazyColumn(Modifier.weight(1f)) {
        item { Text(stringResource(R.string.document_account), style = MaterialTheme.typography.titleSmall) }
        items(state.accounts, key = { "account-${it.id}" }) { account ->
            ListItem(
                headlineContent = { Text(account.displayName) },
                supportingContent = { Text(account.serverUrl) },
                trailingContent = {
                    if (account.id ==
                        state.accountId
                    ) {
                        Text(stringResource(R.string.document_selected))
                    }
                },
                modifier = Modifier.clickable(enabled = enabled) { onAccount(account.id) },
            )
        }
        item { Text(stringResource(R.string.document_destination), style = MaterialTheme.typography.titleSmall) }
        items(state.spaces, key = { "space-${it.driveId}" }) { space ->
            ListItem(
                headlineContent = { Text(space.name) },
                trailingContent = {
                    if (space.driveId ==
                        state.spaceId
                    ) {
                        Text(stringResource(R.string.document_selected))
                    }
                },
                modifier = Modifier.clickable(enabled = enabled) { onSpace(space.driveId) },
            )
        }
        item {
            Text((state.restoredPath ?: state.trail.lastOrNull()?.path).takeUnless { it.isNullOrEmpty() } ?: "/")
            if (state.trail.isNotEmpty()) {
                TextButton(
                    onClick = onUp,
                    enabled = enabled,
                ) { Text(stringResource(R.string.document_up_folder)) }
            }
        }
        items(state.folders, key = { "folder-${it.remoteId}" }) { folder ->
            ListItem(
                headlineContent = { Text(folder.name) },
                leadingContent = { Icon(Icons.Default.Folder, null) },
                modifier = Modifier.clickable(enabled = enabled) { onFolder(folder) },
            )
        }
    }
}
