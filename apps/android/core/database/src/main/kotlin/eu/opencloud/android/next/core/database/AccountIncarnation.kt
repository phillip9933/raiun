package eu.opencloud.android.next.core.database

import androidx.room.withTransaction
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.UUID

/** Capability/display refresh preserves ownership; replacing the security identity revokes its durable jobs. */
internal suspend fun FileBrowserDatabase.upsertOwnedAccount(account: AccountEntity) =
    withTransaction {
        val previous = vaultOfflineGroupDao().storedAccount(account.id)
        if (previous != null && accountIdentityDigest(previous) != accountIdentityDigest(account)) {
            vaultOfflineGroupDao().cancelOwnerTransfers(account.id)
            vaultOfflineGroupDao().deleteOwner(account.id)
        }
        accountDao().upsert(account)
        ensureAccountIncarnation(account.id)
        Unit
    }

/** Invoke only inside this database's Room transaction, with an active account already checked. */
internal suspend fun FileBrowserDatabase.ensureAccountIncarnation(accountId: String): AccountIncarnationEntity {
    val dao = vaultOfflineGroupDao()
    dao.insertOwner(AccountIncarnationEntity(accountId, UUID.randomUUID().toString().replace("-", "")))
    return requireNotNull(dao.owner(accountId))
}

/** Exact saved security tuple; callers of the sync boundary own endpoint normalization. */
internal fun accountIdentityDigest(account: AccountEntity): String =
    groupDigest("raiun-account-owner-v1", account.id, account.serverUrl, account.userId, account.authenticationType)

internal fun groupDigest(vararg fields: String): String {
    val framed = ByteArrayOutputStream()
    DataOutputStream(framed).use { output ->
        fields.forEach { field ->
            val bytes = field.toByteArray(Charsets.UTF_8)
            output.writeInt(bytes.size)
            output.write(bytes)
        }
    }
    return MessageDigest.getInstance("SHA-256").digest(framed.toByteArray()).joinToString("") { "%02x".format(it) }
}
