package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class AccountRemovalTest {
    @Test fun tombstoneHidesAccountSurvivesRestartAndRefusesReactivationUntilCleanupCompletes() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val name = "removal-${UUID.randomUUID()}.db"

            fun open() = Room.databaseBuilder(context, FileBrowserDatabase::class.java, name).build()
            val account = AccountEntity("a", "https://cloud.example", "user", "User", "OIDC", false)
            val other = account.copy(id = "b", userId = "other")
            var database = open()
            try {
                database.upsertOwnedAccount(account)
                database.upsertOwnedAccount(other)
                var store = FileBrowserStore(database)
                val originalOwner = store.vaultOfflineGroups().captureOwner(account.id)
                assertTrue(store.beginAccountRemoval(account.id))
                assertNull(store.account(account.id))
                assertEquals(listOf(other), store.activeAccounts())
                assertTrue(store.hasOtherAccountAtServer(account))
                assertEquals(originalOwner, store.accountRemovalOwner(account.id))
                database.close()
                database = open()
                store = FileBrowserStore(database)
                assertTrue(store.isAccountRemovalPending(account.id))
                assertEquals(originalOwner, store.accountRemovalOwner(account.id))
                assertTrue(store.beginAccountRemoval(account.id))
                var rejected = false
                try {
                    database.upsertOwnedAccount(account)
                } catch (_: IllegalStateException) {
                    rejected = true
                }
                assertTrue(rejected)
                assertEquals(
                    listOf(account.copy(isActive = false, removalPending = true)),
                    store.pendingAccountRemovals(),
                )
                store.removeAccount(account.id)
                store.removeAccount(account.id)
                assertFalse(store.isAccountRemovalPending(account.id))
                assertNotNull(store.account(other.id))
                database.upsertOwnedAccount(account)
                assertNotNull(store.account(account.id))
            } finally {
                database.close()
                context.deleteDatabase(name)
            }
        }
}
