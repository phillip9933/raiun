package eu.opencloud.android.next.core.database

/** Drops terminal group/member history after its transfer row is gone; publication receipts remain independent. */
internal fun FileBrowserDatabase.compactTerminalOfflineGroupHistory(accountId: String) {
    openHelper.writableDatabase
        .compileStatement(
            "DELETE FROM vault_offline_groups WHERE accountId = ? " +
                "AND state IN ('SUCCEEDED','FAILED','CANCELLED') AND activeSlot IS NULL " +
                "AND pendingPublicationId IS NULL " +
                "AND NOT EXISTS (SELECT 1 FROM transfers t WHERE t.id = vault_offline_groups.id) " +
                "AND NOT EXISTS (SELECT 1 FROM vault_offline_group_publications p " +
                "WHERE p.groupId = vault_offline_groups.id " +
                "AND p.journalResolved = 0)",
        ).use { statement ->
            statement.bindString(1, accountId)
            statement.executeUpdateDelete()
        }
}
