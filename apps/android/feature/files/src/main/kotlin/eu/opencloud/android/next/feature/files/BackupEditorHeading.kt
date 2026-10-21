package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Column
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.database.TransferEntity

@Composable
internal fun BackupEditorHeading(
    backup: FolderBackupEntity?,
    transfers: List<TransferEntity>,
) {
    Column {
        Text(
            stringResource(if (backup == null) R.string.backup_settings_add else R.string.backup_settings_manage),
            style = MaterialTheme.typography.headlineSmall,
        )
        backup?.let {
            BackupSyncInfo(it, transfers)
        }
    }
}
