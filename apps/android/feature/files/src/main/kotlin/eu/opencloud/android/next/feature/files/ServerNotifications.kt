package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
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
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.repeatOnLifecycle
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.network.ServerNotification
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.ServerNotificationsRepository
import eu.opencloud.android.next.core.ui.displayServerDate
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

@Composable
@Suppress("TooGenericExceptionCaught") // UI boundary preserves cancellation and displays safe server errors.
internal fun ServerNotificationsBell(accountId: String, onOpenShares: () -> Unit) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    val scope = rememberCoroutineScope()
    val repository = remember(context) { ServerNotificationsRepository(context) }
    val mutex = remember(accountId) { Mutex() }
    var notifications by remember(accountId) { mutableStateOf(emptyList<ServerNotification>()) }
    var error by remember(accountId) { mutableStateOf<String?>(null) }
    var loading by remember(accountId) { mutableStateOf(false) }
    var opened by remember(accountId) { mutableStateOf(false) }
    val update: suspend (List<String>?) -> Unit = { ids ->
        mutex.withLock {
            loading = true
            error = null
            try {
                notifications =
                    withContext(Dispatchers.IO) {
                        if (ids != null) repository.markRead(accountId, ids)
                        repository.list(accountId)
                    }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                error = failure.toOpenCloudError().safeMessage(context)
            } finally {
                loading = false
            }
        }
    }
    LaunchedEffect(accountId, owner) {
        owner.lifecycle.repeatOnLifecycle(Lifecycle.State.RESUMED) {
            while (true) {
                update(null)
                delay(30000)
            }
        }
    }
    IconButton(onClick = {
        opened = true
        scope.launch { update(null) }
    }) {
        BadgedBox(
            badge = { if (notifications.isNotEmpty()) Badge { Text(notifications.size.coerceAtMost(99).toString()) } },
        ) {
            Icon(Icons.Default.Notifications, stringResource(R.string.notifications_title))
        }
    }
    if (opened) {
        Dialog(onDismissRequest = { opened = false }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            NotificationInbox(
                notifications,
                loading,
                error,
                { opened = false },
                { scope.launch { update(null) } },
                { ids -> scope.launch { update(ids) } },
                {
                    opened = false
                    onOpenShares()
                },
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Inbox state and explicit notification actions.
fun NotificationInbox(
    notifications: List<ServerNotification>,
    loading: Boolean,
    error: String?,
    onClose: () -> Unit,
    onRefresh: () -> Unit,
    onRead: (List<String>) -> Unit,
    onOpenShares: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(modifier.fillMaxSize(), topBar = {
        TopAppBar(title = { Text(stringResource(R.string.notifications_title)) }, navigationIcon = {
            IconButton(
                onClick = onClose,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.document_back)) }
        }, actions = {
            IconButton(onClick = onRefresh, enabled = !loading) {
                Icon(Icons.Default.Refresh, stringResource(R.string.notifications_refresh))
            }
        })
    }) { padding ->
        Column(Modifier.padding(padding).padding(OpenCloudDimensions.SpacingMd)) {
            if (loading) LinearProgressIndicator()
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (notifications.isEmpty() && !loading && error == null) Text(stringResource(R.string.notifications_empty))
            if (notifications.isNotEmpty()) {
                TextButton(
                    enabled = !loading,
                    onClick = { onRead(notifications.map { it.id }) },
                ) { Text(stringResource(R.string.notifications_read_all)) }
            }
            LazyColumn(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                items(notifications, key = { it.id }) { item -> NotificationCard(item, !loading, onRead, onOpenShares) }
            }
        }
    }
}

@Composable
private fun NotificationCard(
    item: ServerNotification,
    enabled: Boolean,
    onRead: (List<String>) -> Unit,
    onOpenShares: () -> Unit,
) {
    Card {
        Column(
            Modifier.padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            Text(item.subject, style = MaterialTheme.typography.titleSmall)
            if (item.message.isNotBlank()) Text(item.message)
            Text(displayServerDate(item.dateTime), style = MaterialTheme.typography.bodySmall)
            Row {
                if (item.isShare) {
                    TextButton(
                        onClick = onOpenShares,
                    ) { Text(stringResource(R.string.notifications_open_shares)) }
                }
                TextButton(enabled = enabled, onClick = {
                    onRead(listOf(item.id))
                }) { Text(stringResource(R.string.notifications_read)) }
            }
        }
    }
}
