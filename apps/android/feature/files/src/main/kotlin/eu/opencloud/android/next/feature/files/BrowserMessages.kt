package eu.opencloud.android.next.feature.files

import android.text.format.Formatter
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.database.typedState

@Composable
internal fun browserQuotaSummary(
    used: Long?,
    total: Long?,
): String {
    val context = LocalContext.current
    return when {
        used == null -> stringResource(R.string.browser_usage_unavailable)
        total == null -> stringResource(R.string.browser_storage_used, Formatter.formatShortFileSize(context, used))
        else ->
            stringResource(
                R.string.browser_storage_used_total,
                Formatter.formatShortFileSize(context, used),
                Formatter.formatShortFileSize(context, total),
            )
    }
}

@Composable
internal fun browserTransferSummary(transfer: TransferEntity): String =
    when (transfer.typedState) {
        TransferState.CONFLICT -> stringResource(R.string.browser_transfer_conflict, transfer.displayName)
        TransferState.FAILED -> stringResource(R.string.browser_transfer_failed, transfer.displayName)
        TransferState.UNKNOWN -> stringResource(R.string.browser_transfer_unknown, transfer.displayName)
        TransferState.RETRY -> stringResource(R.string.browser_transfer_retrying, transfer.displayName)
        else ->
            stringResource(
                R.string.browser_transfer_direction,
                stringResource(
                    when (transfer.direction) {
                        "UPLOAD" -> R.string.browser_direction_upload
                        "DOWNLOAD" -> R.string.browser_direction_download
                        else -> R.string.browser_direction_transfer
                    },
                ),
                transfer.displayName,
            )
    }
