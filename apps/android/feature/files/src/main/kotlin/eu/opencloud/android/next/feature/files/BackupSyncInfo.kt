package eu.opencloud.android.next.feature.files

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.sync.BackupScanDiagnostics
import java.text.DateFormat
import java.util.Date

@Composable
internal fun BackupSyncInfo(
    backup: FolderBackupEntity,
    transfers: List<TransferEntity>,
) {
    val context = LocalContext.current
    val diagnostics = remember(context) { BackupScanDiagnostics(context) }
    val failureFlow = remember(backup, diagnostics) { diagnostics.observe(backup) }
    val failure by failureFlow.collectAsState(initial = diagnostics.read(backup))
    androidx.compose.foundation.layout.Column {
        failure?.let { BackupScanFailureInfo(it) }
        Text(
            if (backup.lastSafeScanEpochMillis >
                0
            ) {
                stringResource(
                    R.string.backup_settings_last_checked_through,
                    backupDate(backup.lastSafeScanEpochMillis),
                )
            } else {
                stringResource(R.string.backup_settings_not_scanned)
            },
            style = MaterialTheme.typography.bodySmall,
        )
        val matching =
            transfers.filter {
                it.accountId == backup.accountId &&
                    it.spaceId == backup.spaceId &&
                    it.direction == "UPLOAD" &&
                    it.sourceUri?.startsWith(backup.sourceTreeUri.trimEnd('/') + "/document/") == true &&
                    it.destinationPath.startsWith(backup.destinationPath.trimEnd('/') + "/")
            }
        val active = matching.count { it.state in setOf("QUEUED", "RUNNING", "RETRY") }
        val failed = matching.count { it.state in setOf("FAILED", "CONFLICT") }
        if (active > 0) {
            Text(
                pluralStringResource(R.plurals.backup_settings_uploads_pending, active, active),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (failed >
            0
        ) {
            Text(
                pluralStringResource(R.plurals.backup_settings_uploads_need_attention, failed, failed),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        val lastCompletedUpload =
            matching.filter { it.state == "SUCCEEDED" }.maxOfOrNull { it.updatedAtEpochMillis }
        if (lastCompletedUpload != null) {
            Text(
                stringResource(R.string.backup_settings_last_completed_upload, backupDate(lastCompletedUpload)),
                style = MaterialTheme.typography.bodySmall,
            )
        }
        if (active == 0 &&
            failed == 0 &&
            failure == null
        ) {
            Text(
                stringResource(
                    if (backup.enabled) R.string.backup_settings_watching else R.string.backup_settings_paused,
                ),
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun BackupScanFailureInfo(report: eu.opencloud.android.next.core.sync.BackupScanFailure) {
    val context = LocalContext.current
    androidx.compose.foundation.layout.Column {
        Text(
            stringResource(R.string.backup_scan_failed_at, backupDate(report.occurredAtEpochMillis)),
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
        )
        Text(
            when (report.error) {
                OpenCloudError.SourceUnavailable -> stringResource(R.string.backup_scan_source_unavailable)
                OpenCloudError.SourcePermissionDenied -> stringResource(R.string.backup_scan_source_permission)
                else -> report.error.safeMessage(context)
            },
            color = MaterialTheme.colorScheme.error,
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

private fun backupDate(timestamp: Long) =
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(Date(timestamp))
