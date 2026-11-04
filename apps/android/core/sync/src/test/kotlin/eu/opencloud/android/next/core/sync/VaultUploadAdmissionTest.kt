package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.nio.file.Files

@RunWith(RobolectricTestRunner::class)
class VaultUploadAdmissionTest {
    private val context = RuntimeEnvironment.getApplication()
    private val root = Files.createTempDirectory("vault-upload-admission").toFile()
    private val payloads = VaultUploadStore(root)
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private val location =
        VaultLocation(
            "account",
            "",
            VaultLocationKind.FOLDER_VAULT,
            "drive",
            "vault-id",
            "source-id",
            "https://example.test/",
            "https://example.test/dav/",
            "public.vault",
            true,
        )

    @Before fun setUp() {
        database =
            Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).allowMainThreadQueries().build()
        store = FileBrowserStore(database)
        runBlocking {
            database.accountDao().upsert(
                AccountEntity("account", "https://example.test", "user", "User", "BASIC", false),
            )
        }
    }

    @After fun clean() {
        database.close()
        root.deleteRecursively()
    }

    @Test fun replacementAdmissionPersistsCapturedETagWithoutUnconditionalOverwriteOrSource() =
        runBlocking {
            val job = job()
            var scheduled = false
            var acknowledged = false
            assertEquals(
                job.id,
                enqueuePreparedVaultUpload(
                    context,
                    payloads,
                    job,
                    { true },
                    store,
                    schedule = {
                        assertEquals(job.expectedETag, it.expectedETag)
                        scheduled = true
                    },
                    onCommitted = { acknowledged = true },
                ),
            )
            val row = requireNotNull(store.transfer(job.id))
            assertEquals(job.expectedETag, row.expectedETag)
            assertFalse(row.overwrite)
            assertEquals(null, row.sourceUri)
            assertEquals(null, row.resourceId)
            assertTrue(scheduled && acknowledged)
            assertEquals(job, VaultUploadStore(root).read(job.id))
        }

    @Test fun cancellationAfterRoomCommitRetainsPayloadAndConsumesIssuedVersionForReconciliation() {
        val job = job()
        var acknowledged = false
        assertThrows(CancellationException::class.java) {
            runBlocking {
                enqueuePreparedVaultUpload(
                    context,
                    payloads,
                    job,
                    { true },
                    store,
                    schedule = { throw CancellationException("Synthetic interruption after Room commit") },
                    onCommitted = { acknowledged = true },
                )
            }
        }
        assertTrue(acknowledged)
        assertEquals(job, VaultUploadStore(root).read(job.id))
        assertEquals("QUEUED", runBlocking { store.transfer(job.id) }?.state)
    }

    @Test fun revokedAccountBeforeAdmissionDeletesPreparedPayloadWithoutScheduling() {
        val job = job()
        var scheduled = false
        assertThrows(OpenCloudException::class.java) {
            runBlocking {
                enqueuePreparedVaultUpload(context, payloads, job, { false }, store, schedule = {
                    scheduled =
                        true
                })
            }
        }
        assertFalse(scheduled)
        assertTrue(payloads.ids().isEmpty())
        assertEquals(null, runBlocking { store.transfer(job.id) })
    }

    @Test fun accountCleanupDuringAdmissionCannotResurrectPreparedPayload() =
        runBlocking {
            val job = job()
            var acknowledged = false
            enqueuePreparedVaultUpload(
                context,
                payloads,
                job,
                { true },
                store,
                schedule = { payloads.forgetAccount(job.location.accountId) },
                onCommitted = { acknowledged = true },
            )
            assertFalse(acknowledged)
            assertTrue(payloads.ids().isEmpty())
            assertEquals("CANCELLED", store.transfer(job.id)?.state)
        }

    private fun job() =
        payloads.prepare(location, "public.vault/enc-name", "\"issued-version\"", vaultProofDigest("proof")) {
            it.write(ByteArray(64) { 7 })
        }
}
