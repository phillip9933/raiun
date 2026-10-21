package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.ItemActivity
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.sync.ItemActivitiesRepository
import kotlinx.coroutines.CancellationException

@Composable
fun ItemActivitiesAction(
    accountId: String,
    itemId: String,
    name: String,
    modifier: Modifier = Modifier,
) {
    var open by remember(accountId, itemId) { mutableStateOf(false) }
    TextButton(onClick = { open = true }, modifier = modifier) { Text(stringResource(R.string.activities_title)) }
    if (open) {
        val context = LocalContext.current
        val repository = remember(context) { ItemActivitiesRepository(context) }
        ItemActivitiesDialog(name, { open = false }) { repository.list(accountId, itemId) }
    }
}

@Composable
@Suppress("TooGenericExceptionCaught") // Network failures are shown without exposing server response bodies.
fun ItemActivitiesDialog(
    name: String,
    onBack: () -> Unit,
    load: suspend () -> List<ItemActivity>,
) {
    var rows by remember(name) { mutableStateOf<List<ItemActivity>>(emptyList()) }
    var busy by remember(name) { mutableStateOf(true) }
    var error by remember(name) { mutableStateOf<Int?>(null) }
    var retry by remember(name) { mutableIntStateOf(0) }
    val currentLoad by rememberUpdatedState(load)
    LaunchedEffect(name, retry) {
        busy = true
        error = null
        rows = emptyList()
        try {
            rows = currentLoad()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: TransferHttpException) {
            error =
                if (failure.statusCode in setOf(404, 405, 501)) {
                    R.string.activities_unavailable
                } else {
                    R.string.activities_error
                }
        } catch (_: Exception) {
            error = R.string.activities_error
        } finally {
            busy = false
        }
    }
    AlertDialog(
        onDismissRequest = onBack,
        title = {
            Column {
                Text(stringResource(R.string.activities_title))
                Text(name, style = MaterialTheme.typography.bodyMedium)
            }
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                when {
                    busy -> {
                        Text(stringResource(R.string.activities_loading))
                        LinearProgressIndicator()
                    }
                    error != null -> Text(stringResource(requireNotNull(error)))
                    rows.isEmpty() -> Text(stringResource(R.string.activities_empty))
                    else ->
                        LazyColumn(
                            Modifier.heightIn(max = OpenCloudDimensions.TouchTarget * 8),
                            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
                        ) {
                            items(rows, key = { it.id }) { row ->
                                Column {
                                    Text(row.message)
                                    Text(
                                        displayServerDate(row.recordedTime),
                                        style = MaterialTheme.typography.bodySmall,
                                    )
                                }
                            }
                            item {
                                Text(
                                    stringResource(R.string.activities_limit),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                }
            }
        },
        confirmButton = { TextButton(onClick = onBack) { Text(stringResource(R.string.activities_back)) } },
        dismissButton = {
            TextButton(enabled = !busy, onClick = { retry++ }) {
                Text(stringResource(if (error == null) R.string.activities_refresh else R.string.activities_retry))
            }
        },
    )
}
