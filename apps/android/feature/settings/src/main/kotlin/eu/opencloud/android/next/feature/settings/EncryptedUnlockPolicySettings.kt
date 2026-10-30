package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Card
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import eu.opencloud.android.next.core.security.VaultUnlockPolicy
import kotlinx.coroutines.CancellationException

@Composable
internal fun EncryptedUnlockPolicySettings() {
    val context = LocalContext.current
    val policy = remember(context) { VaultUnlockPolicy(context) }
    var askEveryTime by remember(context) { mutableStateOf(policy.askEveryTime()) }
    var failed by remember(context) { mutableStateOf(false) }
    Column {
        Card(Modifier.fillMaxWidth()) {
            ListItem(
                modifier =
                    Modifier.toggleable(
                        value = askEveryTime,
                        role = Role.Switch,
                        onValueChange = { value ->
                            try {
                                policy.setAskEveryTime(value)
                                askEveryTime = policy.askEveryTime()
                                failed = false
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (_: Exception) {
                                askEveryTime = policy.askEveryTime()
                                failed = true
                            }
                        },
                    ),
                headlineContent = { Text(stringResource(R.string.settings_encrypted_ask_every_time)) },
                supportingContent = { Text(stringResource(R.string.settings_encrypted_unlock_session_explanation)) },
                trailingContent = { Switch(checked = askEveryTime, onCheckedChange = null) },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
        }
        if (failed) {
            Text(
                stringResource(R.string.settings_encrypted_unlock_policy_failed),
                color = MaterialTheme.colorScheme.error,
            )
        }
    }
}
