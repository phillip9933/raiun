package eu.opencloud.android.next.core.database

import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase

/** Adds only durable opaque ownership; existing account/transfer/queue/resource rows are not rewritten. */
val MIGRATION_26_27 =
    object : Migration(26, 27) {
        override fun migrate(db: SupportSQLiteDatabase) {
            GROUP_TABLES.forEach(db::execSQL)
            GROUP_INDEXES.forEach { index ->
                val unique = if (index.unique) "UNIQUE " else ""
                db.execSQL("CREATE ${unique}INDEX ${index.name} ON ${index.table}(${index.columns})")
            }
            db.execSQL(
                "INSERT INTO account_incarnations(accountId, incarnation) " +
                    "SELECT id, lower(hex(randomblob(16))) FROM accounts",
            )
        }
    }

private data class GroupIndex(
    val name: String,
    val table: String,
    val columns: String,
    val unique: Boolean = false,
)

private val GROUP_INDEXES =
    listOf(
        GroupIndex(
            "index_account_incarnations_accountId_incarnation",
            "account_incarnations",
            "accountId,incarnation",
            true,
        ),
        GroupIndex("index_vault_offline_groups_accountId_state_id", "vault_offline_groups", "accountId,state,id"),
        GroupIndex(
            "index_vault_offline_groups_accountId_accountIncarnation_id",
            "vault_offline_groups",
            "accountId,accountIncarnation,id",
            true,
        ),
        GroupIndex(
            "index_vault_offline_groups_accountId_driveId_remoteVaultId_activeSlot",
            "vault_offline_groups",
            "accountId,driveId,remoteVaultId,activeSlot",
            true,
        ),
        GroupIndex("index_vault_offline_group_members_memberId", "vault_offline_group_members", "memberId", true),
        GroupIndex(
            "index_vault_offline_group_members_groupId_state_sequence",
            "vault_offline_group_members",
            "groupId,state,sequence",
        ),
        GroupIndex(
            "index_vault_offline_group_publications_accountId_accountIncarnation",
            "vault_offline_group_publications",
            "accountId,accountIncarnation",
        ),
        GroupIndex(
            "index_vault_offline_group_publications_accountId_journalResolved_publicationId",
            "vault_offline_group_publications",
            "accountId,journalResolved,publicationId",
        ),
        GroupIndex(
            "index_vault_offline_group_publications_groupId_publicationId",
            "vault_offline_group_publications",
            "groupId,publicationId",
        ),
    )

private val GROUP_TABLES =
    listOf(
        """
        CREATE TABLE account_incarnations (
          accountId TEXT NOT NULL, incarnation TEXT NOT NULL, PRIMARY KEY(accountId),
          FOREIGN KEY(accountId) REFERENCES accounts(id) ON UPDATE NO ACTION ON DELETE CASCADE
        )
        """.trimIndent(),
        """
        CREATE TABLE vault_offline_groups (
          id TEXT NOT NULL PRIMARY KEY,
          accountId TEXT NOT NULL,
          accountIncarnation TEXT NOT NULL,
          driveId TEXT NOT NULL,
          remoteVaultId TEXT NOT NULL,
          accountIdentityDigest TEXT NOT NULL,
          identityDigest TEXT NOT NULL,
          descriptorId TEXT NOT NULL,
          descriptorDigest TEXT NOT NULL,
          baseOfflineRootDigest TEXT NOT NULL,
          planId TEXT NOT NULL,
          sealedPlanDigest TEXT,
          sealedMemberCount INTEGER,
          sealedFileCount INTEGER,
          sealedCiphertextBytes INTEGER,
          stagedMemberCount INTEGER NOT NULL,
          stagingChainDigest TEXT NOT NULL,
          state TEXT NOT NULL,
          revision INTEGER NOT NULL,
          attemptId TEXT,
          pendingPublicationId TEXT,
          activeSlot INTEGER,
          errorCode TEXT,
          createdAtEpochMillis INTEGER NOT NULL,
          updatedAtEpochMillis INTEGER NOT NULL,
          FOREIGN KEY(accountId,accountIncarnation) REFERENCES account_incarnations(accountId,incarnation)
            ON UPDATE NO ACTION ON DELETE CASCADE
        )
        """.trimIndent(),
        """
        CREATE TABLE vault_offline_group_members (
          groupId TEXT NOT NULL,
          sequence INTEGER NOT NULL,
          memberId TEXT NOT NULL,
          descriptorDigest TEXT NOT NULL,
          kind TEXT NOT NULL,
          state TEXT NOT NULL,
          revision INTEGER NOT NULL,
          attemptId TEXT,
          payloadId TEXT,
          checkpointBytes INTEGER NOT NULL,
          ciphertextDigest TEXT,
          errorCode TEXT,
          PRIMARY KEY(groupId,sequence),
          FOREIGN KEY(groupId) REFERENCES vault_offline_groups(id) ON UPDATE NO ACTION ON DELETE CASCADE
        )
        """.trimIndent(),
        """
        CREATE TABLE vault_offline_group_publications (
          publicationId TEXT NOT NULL PRIMARY KEY,
          groupId TEXT NOT NULL,
          accountId TEXT NOT NULL,
          accountIncarnation TEXT NOT NULL,
          identityDigest TEXT NOT NULL,
          descriptorDigest TEXT NOT NULL,
          sealedPlanDigest TEXT NOT NULL,
          sealedMemberCount INTEGER NOT NULL,
          baseOfflineRootDigest TEXT NOT NULL,
          nextOfflineRootDigest TEXT NOT NULL,
          reservedGroupRevision INTEGER NOT NULL,
          state TEXT NOT NULL,
          journalResolved INTEGER NOT NULL,
          createdAtEpochMillis INTEGER NOT NULL,
          updatedAtEpochMillis INTEGER NOT NULL,
          FOREIGN KEY(accountId,accountIncarnation) REFERENCES account_incarnations(accountId,incarnation)
            ON UPDATE NO ACTION ON DELETE CASCADE
        )
        """.trimIndent(),
    )
