package eu.opencloud.android.next.core.database

import androidx.room.migration.Migration
import androidx.room.withTransaction
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Credential admission and removal must share this gate through the final account-row write. */
object AccountRemovalAdmission {
    private val mutex = Mutex()

    suspend fun <T> withLock(action: suspend () -> T): T = mutex.withLock { action() }
}

/** A distinct tombstone survives process death; ordinary activation must never resurrect it. */
val MIGRATION_27_28 =
    object : Migration(27, 28) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL("ALTER TABLE accounts ADD COLUMN removalPending INTEGER NOT NULL DEFAULT 0")
        }
    }

suspend fun FileBrowserStore.isAccountRemovalPending(accountId: String): Boolean =
    database.accountDao().stored(accountId)?.removalPending == true

suspend fun FileBrowserStore.pendingAccountRemovals(): List<AccountEntity> = database.accountDao().pendingRemovals()

/** Retains the original identity and incarnation until every external cleanup stage succeeds. */
suspend fun FileBrowserStore.beginAccountRemoval(accountId: String): Boolean =
    database.withTransaction {
        val account = database.accountDao().stored(accountId) ?: return@withTransaction false
        if (!account.removalPending) {
            database.ensureAccountIncarnation(accountId)
            database.invalidateAccountScopes(accountId)
            database.accountDao().markRemoving(accountId)
        }
        true
    }

suspend fun FileBrowserStore.accountRemovalOwner(accountId: String): VaultGroupOwner? =
    database.withTransaction {
        val account = database.accountDao().stored(accountId) ?: return@withTransaction null
        check(account.removalPending)
        val owner = database.vaultOfflineGroupDao().owner(accountId) ?: return@withTransaction null
        VaultGroupOwner(accountId, owner.incarnation, accountIdentityDigest(account))
    }

/** Includes inactive and removing accounts: shared connection choices still belong to them. */
suspend fun FileBrowserStore.hasOtherAccountAtServer(account: AccountEntity): Boolean =
    database.accountDao().all().any {
        it.id != account.id && it.serverUrl.trimEnd('/') == account.serverUrl.trimEnd('/')
    }

/** Admission needs the saved identity even while hidden, so legacy ID collision checks cannot evade removal. */
suspend fun FileBrowserStore.storedAccountForAdmission(accountId: String): AccountEntity? =
    database.accountDao().stored(accountId)

fun FileBrowserStore.observePendingAccountRemovalCount(): kotlinx.coroutines.flow.Flow<Int> =
    database.accountDao().observePendingRemovalCount()
