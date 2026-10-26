package eu.opencloud.android.next.feature.settings

import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.datastore.NavigationItem
import eu.opencloud.android.next.core.datastore.normalizePinnedNavigationItems

@Composable
internal fun NavigationSettings(
    pinned: List<NavigationItem>,
    onChange: (List<NavigationItem>) -> Unit,
) {
    var dialogOpen by remember { mutableStateOf(false) }
    var draft by remember { mutableStateOf(pinned) }
    Card {
        ListItem(
            headlineContent = { Text(stringResource(R.string.settings_navigation)) },
            colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            trailingContent = {
                FilledTonalButton(onClick = {
                    draft = normalizePinnedNavigationItems(pinned)
                    dialogOpen = true
                }) { Text(stringResource(R.string.settings_navigation_edit)) }
            },
        )
    }
    if (dialogOpen) {
        AlertDialog(
            onDismissRequest = { dialogOpen = false },
            title = { Text(stringResource(R.string.settings_navigation_pinned)) },
            text = {
                NavigationPinEditor(draft, onChange = { draft = it })
            },
            confirmButton = {
                TextButton(onClick = {
                    onChange(draft)
                    dialogOpen = false
                }) { Text(stringResource(R.string.settings_navigation_save)) }
            },
            dismissButton = {
                TextButton(onClick = { dialogOpen = false }) { Text(stringResource(R.string.settings_cancel)) }
            },
        )
    }
}
