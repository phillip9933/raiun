package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class TransferObserverTest {
    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).allowMainThreadQueries()
            .build()
    private val store = FileBrowserStore(database)
    private val account = AccountEntity("a", "https://example.test", "user", "User", "BASIC", false)
    private val target =
        TransferEntity(
            id = "target",
            accountId = "a",
            spaceId = "s",
            resourceId = "r",
            direction = "DOWNLOAD",
            sourceUri = null,
            destinationPath = "/file",
            displayName = "file",
            mimeType = null,
            bytesTotal = 1,
            state = "RUNNING",
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(account)
            database.accountDao().upsert(account.copy(id = "other"))
            database.transferDao().insert(target)
            repeat(256) { database.transferDao().insert(target.copy(id = "history-$it", state = "SUCCEEDED")) }
        }

    @After fun close() = database.close()

    @Test fun observerIsAccountAndIdScopedAcrossProgressAndCompletion() =
        runBlocking {
            assertNull(store.observeTransfer("other", target.id).first())
            assertNull(store.observeTransfer("a", "missing").first())
            val observed = CompletableDeferred<Unit>()
            val completed =
                async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(5_000) {
                        store
                            .observeTransfer("a", target.id)
                            .onEach {
                                if (it?.state == "RUNNING") observed.complete(Unit)
                            }.first { it?.state == "SUCCEEDED" }
                    }
                }
            withTimeout(5_000) { observed.await() }
            database.transferDao().update(target.copy(id = "history-0", updatedAtEpochMillis = 1, state = "SUCCEEDED"))
            val finished = target.copy(updatedAtEpochMillis = 2, state = "SUCCEEDED")
            database.transferDao().update(finished)
            assertEquals(finished, completed.await())
        }

    @Test fun accountDeactivationEndsTheObserverWithoutDeletingItsTransfer() =
        runBlocking {
            val observed = CompletableDeferred<Unit>()
            val revoked =
                async(start = CoroutineStart.UNDISPATCHED) {
                    withTimeout(5_000) {
                        store
                            .observeTransfer("a", target.id)
                            .onEach {
                                if (it != null) observed.complete(Unit)
                            }.first { it == null }
                    }
                }
            withTimeout(5_000) { observed.await() }
            database.accountDao().upsert(account.copy(isActive = false))
            assertNull(revoked.await())
            assertEquals(target, database.transferDao().findById(target.id))
        }
}
