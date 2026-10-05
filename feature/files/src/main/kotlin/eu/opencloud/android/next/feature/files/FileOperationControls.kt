package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.ui.BrowserPlacementBar
import eu.opencloud.android.next.core.ui.BrowserPlacementBarState
import eu.opencloud.android.next.core.ui.FileNameConflictDialog

@Composable
@Suppress("LongParameterList") // Keep each action callback explicit at this single browser integration boundary.
internal fun FileOperationControls(
    state: FileBrowserUiState,
    place: () -> Unit,
    cancel: () -> Unit,
    retry: (String) -> Unit,
    dismiss: (String) -> Unit,
    keepBothConflict: () -> Unit = {},
) {
    if (state.clipboard == null && state.operations.isEmpty()) return
    Surface(color = MaterialTheme.colorScheme.surfaceContainer) {
        Column(
            Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            state.placementConflict?.let { conflict ->
                FileNameConflictDialog(
                    name = conflict.source.name,
                    proposedName = conflict.suggestedName,
                    busy = state.placementBusy,
                    secureWindow = false,
                    onKeepBoth = keepBothConflict,
                    onCancel = cancel,
                )
            }
            state.clipboard?.let { source ->
                BrowserPlacementBar(
                    sourceSummary =
                        if (state.clipboardItems.size > 1) {
                            pluralStringResource(
                                R.plurals.file_operation_choose_destination_many,
                                state.clipboardItems.size,
                                state.clipboardItems.size,
                            )
                        } else {
                            stringResource(R.string.file_operation_choose_destination_one, source.name)
                        },
                    state =
                        BrowserPlacementBarState(
                            actionLabel =
                                if (state.moving) {
                                    R.string.file_operation_move_here
                                } else {
                                    R.string.file_operation_copy_here
                                },
                            cancelLabel = R.string.file_operation_cancel,
                            busy = state.placementBusy,
                            showCancel = state.placementConflict == null,
                        ),
                    onPlace = place,
                    onCancel = cancel,
                )
            }
            state.operations.firstOrNull()?.let { operation ->
                Text(
                    if (operation.state in
                        setOf("NEEDS_ATTENTION", "BLOCKED_VAULT")
                    ) {
                        operation.error.orEmpty()
                    } else {
                        stringResource(
                            R.string.file_operation_verifying,
                            operation.sourcePath.substringAfterLast('/'),
                        )
                    },
                )
                if (operation.state in setOf("NEEDS_ATTENTION", "BLOCKED_VAULT")) {
                    Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                        if (operation.state == "NEEDS_ATTENTION") {
                            FilledTonalButton(onClick = { retry(operation.id) }) {
                                Text(stringResource(R.string.file_operation_check_again))
                            }
                        }
                        OutlinedButton(onClick = { dismiss(operation.id) }) {
                            Text(stringResource(R.string.file_operation_dismiss))
                        }
                    }
                }
            }
        }
    }
}
