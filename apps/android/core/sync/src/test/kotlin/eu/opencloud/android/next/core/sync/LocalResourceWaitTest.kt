package eu.opencloud.android.next.core.sync

import androidx.room.Room
import androidx.room.withTransaction
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.StaleResourceException
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.security.AppLock
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class LocalResourceWaitTest {
    private val context = RuntimeEnvironment.getApplication()
    private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
    private val store = FileBrowserStore(database)
    private val resource =
        ResourceEntity(
            "a",
            "s",
            "r",
            null,
            "/file",
            "file",
            ResourceKind.FILE,
            "text/plain",
            1,
            "\"version\"",
            0,
            0,
            hasLocalCopy = true,
            localPath = "/synthetic/file",
        )
    private val transfer =
        TransferEntity(
            id = "download",
            accountId = "a",
            spaceId = "s",
            resourceId = "r",
            direction = "DOWNLOAD",
            sourceUri = null,
            destinationPath = "/file",
            displayName = "file",
            mimeType = "text/plain",
            bytesTotal = 1,
            state = "RUNNING",
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )
    private val space =
        SpaceEntity(
            "a",
            "s",
            "Personal",
            "personal",
            null,
            null,
            "root",
            "https://example.test/dav/s",
            null,
            null,
        )

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "User", "BASIC", false))
            database.spaceDao().insert(space)
            database.resourceDao().insert(resource)
            database.transferDao().insert(transfer)
        }

    @After fun close() = database.close()

    @Test fun completionReturnsCurrentAccessibleResourceAfterCacheValidation() =
        runBlocking {
            var validations = 0
            val result =
                async(start = CoroutineStart.UNDISPATCHED) {
                    awaitDownloadedResource(store, resource, transfer.id, { true }) {
                        validations++
                        assertEquals(resource, it)
                        true
                    }
                }
            database.transferDao().update(transfer.copy(state = "SUCCEEDED"))
            assertEquals(resource, withTimeout(5_000) { result.await() })
            assertEquals(1, validations)
        }

    @Test fun explicitLockDuringDownloadNeverReachesCachedBytesAfterReauthentication() =
        runBlocking {
            val lock = AppLock(context)
            val permit = lock.beginAppAction()
            var validations = 0
            val result =
                async(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        awaitDownloadedResource(store, resource, transfer.id, permit) {
                            validations++
                            true
                        }
                        false
                    } catch (failure: IllegalStateException) {
                        failure.message == "File access is locked."
                    }
                }
            lock.lock()
            lock.authenticated()
            database.transferDao().update(transfer.copy(state = "SUCCEEDED"))
            assertTrue(withTimeout(5_000) { result.await() })
            assertEquals(0, validations)
        }

    @Test fun revokedSpaceDuringDownloadCannotReturnItsExistingCachedBytes() =
        runBlocking {
            var validations = 0
            val result =
                async(start = CoroutineStart.UNDISPATCHED) {
                    try {
                        awaitDownloadedResource(store, resource, transfer.id, { true }) {
                            validations++
                            true
                        }
                        false
                    } catch (failure: IllegalStateException) {
                        failure.message == "The resource is unavailable."
                    }
                }
            database.withTransaction {
                database.spaceDao().upsertAll(listOf(space.copy(isDisabled = true)))
                database.transferDao().update(transfer.copy(state = "SUCCEEDED"))
            }
            assertTrue(withTimeout(5_000) { result.await() })
            assertEquals(0, validations)
        }

    @Test fun changedRemoteIdentityDuringDownloadIsRejectedBeforeCacheValidation() =
        runBlocking {
            for (changed in listOf(
                resource.copy(path = "/different"),
                resource.copy(eTag = "\"new-version\""),
                resource.copy(kind = ResourceKind.FOLDER),
            )) {
                database.resourceDao().upsert(resource)
                database.transferDao().update(transfer)
                var validations = 0
                val result =
                    async(start = CoroutineStart.UNDISPATCHED) {
                        try {
                            awaitDownloadedResource(store, resource, transfer.id, { true }) {
                                validations++
                                true
                            }
                            false
                        } catch (_: StaleResourceException) {
                            true
                        }
                    }
                database.withTransaction {
                    database.resourceDao().upsert(changed)
                    database.transferDao().update(transfer.copy(state = "SUCCEEDED"))
                }
                assertTrue(withTimeout(5_000) { result.await() })
                assertEquals(0, validations)
            }
        }

    @Test fun lockingDuringCacheValidationCannotPublishThePreparedResource() =
        runBlocking {
            val lock = AppLock(context)
            val permit = lock.beginAppAction()
            database.transferDao().update(transfer.copy(state = "SUCCEEDED"))
            var rejected = false
            try {
                awaitDownloadedResource(store, resource, transfer.id, permit) {
                    lock.lock()
                    true
                }
            } catch (failure: IllegalStateException) {
                rejected = failure.message == "File access is locked."
            }
            assertTrue(rejected)
        }

    @Test fun cancellingTheWaitPreservesTheIndependentDownloadAndNeverValidatesCache() =
        runBlocking {
            var validations = 0
            val job =
                async(start = CoroutineStart.UNDISPATCHED) {
                    awaitDownloadedResource(store, resource, transfer.id, { true }) {
                        validations++
                        true
                    }
                }
            job.cancelAndJoin()
            assertTrue(job.isCancelled)
            assertEquals(0, validations)
            assertEquals(transfer, database.transferDao().findById(transfer.id))
        }
}
