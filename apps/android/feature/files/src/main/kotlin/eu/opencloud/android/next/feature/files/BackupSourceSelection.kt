package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.FolderBackupEntity

/** Source reselection retains the pair and destination, but never carries a completed scan cursor. */
internal fun backupSourceSelection(
    backup: FolderBackupEntity,
    selectedUri: String?,
    selectedName: String?,
): FolderBackupEntity =
    if (selectedUri == null) {
        backup
    } else {
        backup.copy(
            sourceTreeUri = selectedUri,
            sourceDisplayName = selectedName.orEmpty(),
            lastSafeScanEpochMillis = 0,
        )
    }

/** A delayed permission response cannot rebind a pair edited or removed while the prompt was open. */
internal fun backupSourceSelectionFingerprint(backup: FolderBackupEntity): String =
    eu.opencloud.android.next.core.model
        .cacheIdentity(backup.copy(lastSafeScanEpochMillis = 0).toString())
