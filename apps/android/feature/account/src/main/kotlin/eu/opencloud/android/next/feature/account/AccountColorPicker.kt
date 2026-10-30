package eu.opencloud.android.next.feature.account

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.style.TextOverflow
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.designsystem.theme.AccountAccent
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDarkColorScheme
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudLightColorScheme
import eu.opencloud.android.next.core.model.AccountColor
import eu.opencloud.android.next.core.sync.AccountProfiles
import eu.opencloud.android.next.core.ui.accountAccent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The key owns the draft, I/O scope and dismissal state for exactly one account. */
@Composable
@Suppress("TooGenericExceptionCaught", "SwallowedException")
internal fun AccountColorSetting(account: AccountEntity) {
    key(account.id) {
        val context = LocalContext.current.applicationContext
        val revision by AccountProfiles.colorRevision.collectAsState()
        val scope = rememberCoroutineScope()
        var saved by remember { mutableStateOf<AccountColor?>(null) }
        var loaded by remember { mutableStateOf(false) }
        var open by remember { mutableStateOf(false) }
        var busy by remember { mutableStateOf(false) }
        var failed by remember { mutableStateOf(false) }
        LaunchedEffect(account.id, revision) {
            saved = withContext(Dispatchers.IO) { AccountProfiles.colorChoice(context, account.id) }
            loaded = true
        }
        ListItem(
            headlineContent = { Text(stringResource(R.string.account_color)) },
            supportingContent = {
                Column {
                    Text(stringResource(accountColorLabel(saved)))
                    Text(stringResource(R.string.account_color_device_only))
                }
            },
            leadingContent = { AccountColorSwatch(accountAccent(account.id)) },
            trailingContent = {
                OutlinedButton(onClick = {
                    failed = false
                    open = true
                }, enabled = loaded) {
                    Text(stringResource(R.string.account_color_edit))
                }
            },
        )
        if (open) {
            AccountColorPicker(
                account = account,
                initialChoice = saved,
                busy = busy,
                failed = failed,
                onDismiss = { if (!busy) open = false },
                onSave = { choice ->
                    if (!busy) {
                        busy = true
                        failed = false
                        scope.launch {
                            try {
                                withContext(Dispatchers.IO) {
                                    AccountProfiles.setColorChoice(context, account.id, choice)
                                }
                                saved = choice
                                open = false
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (_: Exception) {
                                failed = true
                            } finally {
                                busy = false
                            }
                        }
                    }
                },
            )
        }
    }
}

@Composable
@Suppress("LongParameterList")
fun AccountColorPicker(
    account: AccountEntity,
    initialChoice: AccountColor?,
    busy: Boolean,
    failed: Boolean,
    onDismiss: () -> Unit,
    onSave: (AccountColor?) -> Unit,
) {
    var draft by remember(account.id) { mutableStateOf(initialChoice) }
    AlertDialog(
        onDismissRequest = { if (!busy) onDismiss() },
        title = { Text(stringResource(R.string.account_color)) },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                Text(stringResource(R.string.account_color_device_only))
                Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
                    AccountColorPreview(account, draft, dark = false, modifier = Modifier.weight(1f))
                    AccountColorPreview(account, draft, dark = true, modifier = Modifier.weight(1f))
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                if (failed) {
                    Text(
                        stringResource(R.string.account_color_save_failed),
                        color = MaterialTheme.colorScheme.error,
                    )
                }
                Column(Modifier.selectableGroup()) {
                    (listOf(null) + AccountColor.entries).forEach { choice ->
                        Row(
                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .heightIn(min = OpenCloudDimensions.TouchTarget)
                                    .selectable(
                                        selected = draft == choice,
                                        enabled = !busy,
                                        role = Role.RadioButton,
                                        onClick = { draft = choice },
                                    ).padding(vertical = OpenCloudDimensions.SpacingXxs),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                        ) {
                            RadioButton(selected = draft == choice, onClick = null, enabled = !busy)
                            AccountColorSwatch(
                                AccountAccent.indicator(
                                    account.id,
                                    MaterialTheme.colorScheme.surface.luminance() < 0.5f,
                                    choice,
                                ),
                            )
                            Text(stringResource(accountColorLabel(choice)), Modifier.weight(1f))
                        }
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = { onSave(draft) }, enabled = !busy) {
                Text(stringResource(R.string.account_color_save))
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !busy) { Text(stringResource(R.string.account_cancel)) }
        },
    )
}

@Composable
private fun AccountColorSwatch(color: Color) {
    Box(Modifier.size(OpenCloudDimensions.CheckboxSize).background(color, CircleShape))
}

/** Illustrates neutral chrome, a slim avatar ring and the selected account's soft tint. */
@Composable
private fun AccountColorPreview(
    account: AccountEntity,
    choice: AccountColor?,
    dark: Boolean,
    modifier: Modifier = Modifier,
) {
    MaterialTheme(colorScheme = if (dark) OpenCloudDarkColorScheme else OpenCloudLightColorScheme) {
        val colors = MaterialTheme.colorScheme
        Surface(modifier = modifier, shape = MaterialTheme.shapes.medium, color = colors.surfaceContainer) {
            Column(
                Modifier.padding(OpenCloudDimensions.SpacingXs),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                Text(
                    stringResource(
                        if (dark) R.string.account_color_dark_preview else R.string.account_color_light_preview,
                    ),
                    style = MaterialTheme.typography.labelMedium,
                )
                Box(
                    Modifier
                        .align(Alignment.End)
                        .border(
                            OpenCloudDimensions.StrokeRegular,
                            AccountAccent.indicator(account.id, dark, choice),
                            CircleShape,
                        ).padding(OpenCloudDimensions.StrokeRegular)
                        .size(OpenCloudDimensions.AvatarSize)
                        .background(colors.surfaceVariant, CircleShape),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(account.displayName.take(1), style = MaterialTheme.typography.labelMedium)
                }
                Surface(
                    shape = MaterialTheme.shapes.small,
                    color = AccountAccent.container(colors.surface, account.id, dark, choice),
                ) {
                    Text(
                        account.displayName,
                        Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingXs),
                        style = MaterialTheme.typography.bodySmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
    }
}

private fun accountColorLabel(choice: AccountColor?): Int =
    when (choice) {
        null -> R.string.account_color_automatic
        AccountColor.TEAL -> R.string.account_color_teal
        AccountColor.JADE -> R.string.account_color_jade
        AccountColor.PURPLE -> R.string.account_color_purple
        AccountColor.ROSE -> R.string.account_color_rose
        AccountColor.AMBER -> R.string.account_color_amber
        AccountColor.BLUE -> R.string.account_color_blue
        AccountColor.FOREST -> R.string.account_color_forest
        AccountColor.PLUM -> R.string.account_color_plum
    }
