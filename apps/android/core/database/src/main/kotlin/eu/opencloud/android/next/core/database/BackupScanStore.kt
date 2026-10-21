package eu.opencloud.android.next.core.database

import androidx.room.withTransaction

/** A scan cannot publish work or settings from a removed, disabled or edited pair. */
class BackupScanStore(
    private val database: FileBrowserDatabase,
) {
    suspend fun requireCurrent(expected: FolderBackupEntity) {
        require(expected.enabled && database.folderBackupDao().findById(expected.id) == expected) {
            "The backup configuration changed."
        }
    }

    suspend fun save(configuration: FolderBackupEntity) =
        database.withTransaction {
            requireDestinationBinding(configuration)
            require(
                !configuration.enabled ||
                    configuration.destinationKind == "SHARED_FOLDER" ||
                    !database.vaultExclusionDao().denies(
                        configuration.accountId,
                        configuration.spaceId,
                        configuration.destinationPath,
                        true,
                    ),
            ) { "Encrypted vault locations are unavailable." }
            val previous = database.folderBackupDao().findById(configuration.id)
            val changed =
                previous != null &&
                    (
                        previous.accountId != configuration.accountId ||
                            previous.spaceId != configuration.spaceId ||
                            previous.destinationPath != configuration.destinationPath ||
                            previous.destinationKind != configuration.destinationKind ||
                            previous.sharedShareId != configuration.sharedShareId ||
                            previous.sharedFolderId != configuration.sharedFolderId
                    )
            if (changed) {
                database.backupReceiptDao().deletePair(configuration.id)
            }
            val revision =
                if (changed) {
                    requireNotNull(previous).destinationRevision + 1
                } else {
                    previous?.destinationRevision
                        ?: 0
                }
            database.folderBackupDao().upsert(configuration.copy(destinationRevision = revision))
        }

    private fun requireDestinationBinding(configuration: FolderBackupEntity) {
        require(configuration.destinationKind in setOf("SPACE", "SHARED_FOLDER"))
        require(
            if (configuration.destinationKind == "SPACE") {
                configuration.sharedShareId == null && configuration.sharedFolderId == null
            } else {
                !configuration.sharedShareId.isNullOrBlank() &&
                    !configuration.sharedFolderId.isNullOrBlank() &&
                    configuration.spaceId.startsWith("shared-folder:")
            },
        ) { "Invalid backup destination binding." }
    }

    suspend fun enqueue(
        expected: FolderBackupEntity,
        transfer: TransferEntity,
    ): TransferEntity =
        database.withTransaction {
            require(expected.enabled && database.folderBackupDao().findById(expected.id) == expected) {
                "The backup configuration changed."
            }
            require(transfer.accountId == expected.accountId && transfer.spaceId == expected.spaceId)
            require(transfer.direction == TransferDirection.UPLOAD.name)
            require(expected.destinationKind == "SPACE" && transfer.locationKind == "SPACE")
            val root = expected.destinationPath.trimEnd('/')
            require(transfer.destinationPath.startsWith("$root/"))
            FileBrowserStore(database).enqueueTransfer(transfer)
        }

    suspend fun complete(
        expected: FolderBackupEntity,
        now: Long,
    ) = database.withTransaction {
        val dao = database.folderBackupDao()
        if (expected.enabled && dao.findById(expected.id) == expected) {
            dao.upsert(expected.copy(lastSafeScanEpochMillis = now))
        }
    }
}
