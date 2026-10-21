package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class ConfirmedShareTest {
    @Test fun `confirmed share is saved without clearing other owned or received shares`() =
        runTest {
            val database =
                Room
                    .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                    .allowMainThreadQueries()
                    .build()
            try {
                val store = FileBrowserStore(database)
                database.accountDao().upsert(
                    AccountEntity("account", "https://cloud.example", "user", "User", "OIDC", false),
                )
                store.replaceShares("account", listOf(share("old"), share("received").copy(sharedWithMe = true)))
                assertTrue(store.saveConfirmedShare(share("new")))
                assertEquals(
                    setOf("old", "received", "new"),
                    store
                        .observeShares("account")
                        .first()
                        .map { it.remoteId }
                        .toSet(),
                )
                store.removeAccount("account")
                assertFalse(store.saveConfirmedShare(share("late")))
                assertTrue(store.observeShares("account").first().isEmpty())
            } finally {
                database.close()
            }
        }

    private fun share(id: String) =
        ShareEntity("account", id, "file", "/file", 3, null, null, null, 1, 0, null, null, false, false)
}
