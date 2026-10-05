package eu.opencloud.android.next.feature.spaces

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.DataUsage
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.DeleteOutline
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Group
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.OpenInBrowser
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.ui.BrowserAction
import eu.opencloud.android.next.core.ui.BrowserActionSheet
import java.math.BigDecimal

enum class SpaceAction(
    val label: Int,
) {
    OPEN(R.string.spaces_open),
    TRASH(R.string.spaces_trash),
    DETAILS(R.string.spaces_details),
    MEMBERS(R.string.spaces_members),
    DOWNLOAD(R.string.spaces_download),
    RENAME(R.string.spaces_rename),
    SUBTITLE(R.string.spaces_subtitle),
    QUOTA(R.string.spaces_quota),
    DISABLE(R.string.spaces_disable),
    ENABLE(R.string.spaces_enable),
    DELETE(R.string.spaces_delete),
    WEB(R.string.spaces_web),
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
internal fun SpaceActionsMenu(
    space: SpaceEntity,
    busy: Boolean,
    browsable: Boolean,
    onAction: (SpaceAction) -> Unit,
) {
    var expanded by rememberSaveable(space.driveId) { mutableStateOf(false) }
    Box {
        IconButton(enabled = !busy, onClick = { expanded = true }) {
            Icon(Icons.Default.MoreVert, stringResource(R.string.spaces_actions, space.name))
        }
        if (expanded) {
            BrowserActionSheet(space.name, onDismiss = { expanded = false }) {
                val actions =
                    if (space.isDisabled) {
                        listOf(SpaceAction.DETAILS, SpaceAction.ENABLE, SpaceAction.DELETE)
                    } else {
                        listOf(
                            SpaceAction.OPEN,
                            SpaceAction.MEMBERS,
                            SpaceAction.DOWNLOAD,
                            SpaceAction.TRASH,
                            SpaceAction.DETAILS,
                            SpaceAction.RENAME,
                            SpaceAction.SUBTITLE,
                            SpaceAction.QUOTA,
                            SpaceAction.DISABLE,
                        )
                    }
                actions
                    .filter {
                        browsable ||
                            it !in
                            listOf(
                                SpaceAction.OPEN,
                                SpaceAction.TRASH,
                                SpaceAction.DOWNLOAD,
                            )
                    }.forEach { action ->
                        if (action == SpaceAction.RENAME) HorizontalDivider()
                        BrowserAction(
                            label = stringResource(action.label),
                            icon = action.icon(),
                            onClick = {
                                expanded = false
                                onAction(action)
                            },
                        )
                    }
            }
        }
    }
}

private fun SpaceAction.icon() =
    when (this) {
        SpaceAction.OPEN -> Icons.Default.FolderOpen
        SpaceAction.TRASH -> Icons.Default.Delete
        SpaceAction.DELETE -> Icons.Default.DeleteOutline
        SpaceAction.DETAILS -> Icons.Default.Info
        SpaceAction.MEMBERS -> Icons.Default.Group
        SpaceAction.DOWNLOAD -> Icons.Default.Download
        SpaceAction.WEB -> Icons.Default.OpenInBrowser
        SpaceAction.RENAME -> Icons.Default.Edit
        SpaceAction.SUBTITLE -> Icons.Default.Description
        SpaceAction.QUOTA -> Icons.Default.DataUsage
        SpaceAction.DISABLE -> Icons.Default.Block
        SpaceAction.ENABLE -> Icons.Default.CheckCircle
    }

@Composable
internal fun SpaceActionDialog(
    space: SpaceEntity,
    action: SpaceAction,
    onDismiss: () -> Unit,
    onSubmit: (String) -> Unit,
) {
    var value by rememberSaveable(space.driveId, action) {
        mutableStateOf(initialSpaceActionValue(space, action))
    }
    val valid = validSpaceActionValue(space, action, value)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(stringResource(action.label)) },
        text = {
            SpaceActionFields(space, action, value, onChange = { value = it })
        },
        confirmButton = {
            if (action == SpaceAction.DETAILS) {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.spaces_close)) }
            } else {
                FilledTonalButton(enabled = valid, onClick = { onSubmit(value) }) {
                    Text(
                        stringResource(
                            if (action in
                                listOf(SpaceAction.DISABLE, SpaceAction.ENABLE, SpaceAction.DELETE, SpaceAction.WEB)
                            ) {
                                action.label
                            } else {
                                R.string.spaces_save
                            },
                        ),
                    )
                }
            }
        },
        dismissButton = {
            if (action !=
                SpaceAction.DETAILS
            ) {
                TextButton(onClick = onDismiss) { Text(stringResource(R.string.spaces_cancel)) }
            }
        },
    )
}

private fun initialSpaceActionValue(
    space: SpaceEntity,
    action: SpaceAction,
): String =
    when (action) {
        SpaceAction.RENAME -> space.name
        SpaceAction.SUBTITLE -> space.description.orEmpty()
        SpaceAction.QUOTA ->
            space.quotaBytes
                ?.toBigDecimal()
                ?.divide(
                    BigDecimal(BYTES_PER_GIB),
                )?.stripTrailingZeros()
                ?.toPlainString()
                .orEmpty()
        else -> ""
    }

private fun validSpaceActionValue(
    space: SpaceEntity,
    action: SpaceAction,
    value: String,
): Boolean =
    when (action) {
        SpaceAction.RENAME -> value.trim().isNotEmpty()
        SpaceAction.QUOTA -> quotaBytes(value) != null
        SpaceAction.DELETE -> value == space.name
        else -> true
    }

@Composable
private fun SpaceActionFields(
    space: SpaceEntity,
    action: SpaceAction,
    value: String,
    onChange: (String) -> Unit,
) {
    Column(Modifier.verticalScroll(rememberScrollState())) {
        when (action) {
            SpaceAction.DETAILS -> SpaceDetails(space)
            SpaceAction.WEB -> Text(stringResource(R.string.spaces_web_summary))
            SpaceAction.DISABLE -> Text(stringResource(R.string.spaces_disable_message, space.name))
            SpaceAction.ENABLE -> Text(stringResource(R.string.spaces_enable_message, space.name))
            SpaceAction.DELETE -> Text(stringResource(R.string.spaces_delete_message, space.name))
            else -> Text(space.name)
        }
        if (action in listOf(SpaceAction.RENAME, SpaceAction.SUBTITLE, SpaceAction.QUOTA, SpaceAction.DELETE)) {
            OutlinedTextField(
                value,
                onValueChange = onChange,
                singleLine = true,
                label = {
                    Text(
                        stringResource(
                            when (action) {
                                SpaceAction.SUBTITLE -> R.string.spaces_subtitle_label
                                SpaceAction.QUOTA -> R.string.spaces_quota_label
                                else -> R.string.spaces_name
                            },
                        ),
                    )
                },
            )
            if (action == SpaceAction.QUOTA) Text(stringResource(R.string.spaces_quota_hint))
        }
    }
}

@Composable
private fun SpaceDetails(space: SpaceEntity) {
    Column {
        Text(space.name)
        space.description?.takeIf(String::isNotBlank)?.let { Text(it) }
        space.ownerName?.let { Text(stringResource(R.string.spaces_owner, it)) }
        Text(stringResource(if (space.isDisabled) R.string.spaces_disabled else R.string.spaces_enabled))
        space.quotaSummary()?.let { Text(stringResource(R.string.spaces_quota_summary, it.used, it.remaining)) }
        space.lastModifiedDateTime?.let { Text(stringResource(R.string.spaces_last_activity, it)) }
    }
}

private const val BYTES_PER_GIB = 1_073_741_824L

internal fun quotaBytes(value: String): Long? =
    try {
        value
            .trim()
            .toBigDecimal()
            .multiply(BigDecimal(BYTES_PER_GIB))
            .longValueExact()
            .takeIf { it > 0 }
    } catch (_: NumberFormatException) {
        null
    } catch (_: ArithmeticException) {
        null
    }
