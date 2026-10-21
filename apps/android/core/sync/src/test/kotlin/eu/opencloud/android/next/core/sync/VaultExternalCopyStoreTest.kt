package eu.opencloud.android.next.core.sync

import android.os.SystemClock
import androidx.work.Configuration
import androidx.work.WorkManager
import androidx.work.testing.SynchronousExecutor
import androidx.work.testing.WorkManagerTestInitHelper
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class VaultExternalCopyStoreTest {
    private val context = RuntimeEnvironment.getApplication()
    private val root get() = File(context.noBackupFilesDir, "vault-external-copies")

    @Before
    fun setUp() {
        VaultExternalCopyStore.cleanupFailureForTests = null
        VaultExternalCopyStore.initializeProcess(context)
        WorkManagerTestInitHelper.initializeTestWorkManager(
            context,
            Configuration.Builder().setExecutor(SynchronousExecutor()).build(),
        )
    }

    @After
    fun tearDown() {
        VaultExternalCopyStore.clockForTests = null
        VaultExternalCopyStore.cleanupFailureForTests = null
        WorkManager
            .getInstance(context)
            .cancelAllWork()
            .result
            .get()
        WorkManagerTestInitHelper.closeWorkDatabase()
        VaultExternalCopyStore.initializeProcess(context)
    }

    @Test
    fun leasePublishesOpaqueReadOnlyUriAndCleanupRemovesPlaintext() =
        runBlocking {
            val lease =
                VaultExternalCopyStore.create(context, "../private note.txt", "text/plain") { output ->
                    output.write("temporary plaintext".encodeToByteArray())
                }
            val id = requireNotNull(lease.uri.lastPathSegment)
            val file = File(root, "$id/content")

            assertEquals("content", lease.uri.scheme)
            assertEquals("${context.packageName}.vault-export", lease.uri.authority)
            assertEquals(1, lease.uri.pathSegments.size)
            assertTrue(id.matches(Regex("[0-9a-f-]{36}")))
            assertEquals("temporary plaintext", file.readText())
            assertEquals(".._private note.txt", VaultExternalCopyStore.find(context, lease.uri)?.displayName)
            assertEquals("text/plain", VaultExternalCopyStore.find(context, lease.uri)?.mimeType)

            lease.cleanup()
            lease.cleanup()

            assertFalse(file.exists())
            assertNull(VaultExternalCopyStore.find(context, lease.uri))
        }

    @Test
    fun writerFailureDeletesPartialExport() {
        assertThrows(IllegalStateException::class.java) {
            runBlocking {
                VaultExternalCopyStore.create(context, "notes.txt", "text/plain") { output ->
                    output.write("partial".encodeToByteArray())
                    error("writer failed")
                }
            }
        }
        assertTrue(root.listFiles().orEmpty().isEmpty())
    }

    @Test
    fun failedPartialCleanupSchedulesRetryAndRemainsUnservable() =
        runBlocking {
            var failCleanup = true
            VaultExternalCopyStore.cleanupFailureForTests = { file -> failCleanup && file.name == "content" }

            assertThrows(IllegalStateException::class.java) {
                runBlocking {
                    VaultExternalCopyStore.create(context, "notes.txt", "text/plain") { output ->
                        output.write("partial".encodeToByteArray())
                        error("writer failed")
                    }
                }
            }

            val directory = root.listFiles().orEmpty().single()
            val uri = android.net.Uri.parse("content://${context.packageName}.vault-export/${directory.name}")
            assertTrue(File(directory, "content").exists())
            assertNull(VaultExternalCopyStore.find(context, uri))
            val work =
                WorkManager
                    .getInstance(context)
                    .getWorkInfosForUniqueWork("vault-external-copy-${directory.name}")
                    .get()
            assertEquals(1, work.size)

            failCleanup = false
            assertTrue(VaultExternalCopyStore.cleanupFromWorker(context, directory.name))
            assertFalse(directory.exists())
        }

    @Test
    fun startupCleanupFailureFailsClosedAndCanRecover() {
        runBlocking {
            VaultExternalCopyStore.create(context, "interrupted.txt", "text/plain") { output ->
                output.write("plaintext".encodeToByteArray())
            }
        }
        VaultExternalCopyStore.cleanupFailureForTests = { file -> file == root }

        assertFalse(VaultExternalCopyStore.initializeProcess(context))
        assertThrows(IllegalStateException::class.java) {
            runBlocking {
                VaultExternalCopyStore.create(context, "blocked.txt", "text/plain") { }
            }
        }
        val work =
            WorkManager
                .getInstance(context)
                .getWorkInfosForUniqueWork("vault-external-copy-__root__")
                .get()
        assertEquals(1, work.size)

        VaultExternalCopyStore.cleanupFailureForTests = null
        assertTrue(VaultExternalCopyStore.cleanupStartupFromWorker(context))
        val lease =
            runBlocking {
                VaultExternalCopyStore.create(context, "available.txt", "text/plain") { }
            }
        lease.cleanup()
    }

    @Test
    fun staleStartupRetryDoesNotDeleteLeaseAfterSuccessfulInitialization(): Unit =
        runBlocking {
            VaultExternalCopyStore.cleanupFailureForTests = { file -> file == root }
            assertFalse(VaultExternalCopyStore.initializeProcess(context))

            VaultExternalCopyStore.cleanupFailureForTests = null
            assertTrue(VaultExternalCopyStore.initializeProcess(context))
            val lease =
                VaultExternalCopyStore.create(context, "current.txt", "text/plain") { output ->
                    output.write("current plaintext".encodeToByteArray())
                }
            val file = File(root, "${lease.uri.lastPathSegment}/content")

            assertTrue(VaultExternalCopyStore.cleanupStartupFromWorker(context))

            assertTrue(file.exists())
            assertNotNull(VaultExternalCopyStore.find(context, lease.uri))
            lease.cleanup()
        }

    @Test
    fun cancellingSuspendingWriterDeletesPartialExport() =
        runBlocking {
            val writing = CompletableDeferred<Unit>()
            val task =
                launch {
                    VaultExternalCopyStore.create(context, "notes.txt", "text/plain") { output ->
                        output.write("partial".encodeToByteArray())
                        writing.complete(Unit)
                        awaitCancellation()
                    }
                }
            writing.await()
            task.cancelAndJoin()

            assertTrue(root.listFiles().orEmpty().isEmpty())
        }

    @Test
    fun cancelledWriterWithFailedCleanupSchedulesRetry() =
        runBlocking {
            val writing = CompletableDeferred<Unit>()
            VaultExternalCopyStore.cleanupFailureForTests = { file -> file.name == "content" }
            val task =
                launch {
                    VaultExternalCopyStore.create(context, "notes.txt", "text/plain") { output ->
                        output.write("partial".encodeToByteArray())
                        writing.complete(Unit)
                        awaitCancellation()
                    }
                }
            writing.await()
            task.cancelAndJoin()

            val directory = root.listFiles().orEmpty().single()
            val work =
                WorkManager
                    .getInstance(context)
                    .getWorkInfosForUniqueWork("vault-external-copy-${directory.name}")
                    .get()
            assertEquals(1, work.size)
            assertTrue(File(directory, "content").exists())
            assertNull(
                VaultExternalCopyStore.find(
                    context,
                    android.net.Uri.parse("content://${context.packageName}.vault-export/${directory.name}"),
                ),
            )
        }

    @Test
    fun startupRemovesInterruptedLeaseAndExpiryRevokesNewReads() =
        runBlocking {
            var now = SystemClock.elapsedRealtime()
            VaultExternalCopyStore.clockForTests = { now }
            val interruptedLease =
                VaultExternalCopyStore.create(context, "interrupted.txt", "text/plain") { output ->
                    output.write("bounded".encodeToByteArray())
                }
            val interruptedFile = File(root, "${interruptedLease.uri.lastPathSegment}/content")
            assertTrue(interruptedFile.exists())

            VaultExternalCopyStore.initializeProcess(context)

            assertFalse(interruptedFile.exists())
            assertNull(VaultExternalCopyStore.find(context, interruptedLease.uri))
            val lease =
                VaultExternalCopyStore.create(context, "notes.txt", "text/plain") { output ->
                    output.write("bounded".encodeToByteArray())
                }
            val file = File(root, "${lease.uri.lastPathSegment}/content")
            assertNotNull(VaultExternalCopyStore.find(context, lease.uri))

            now += VaultExternalCopyStore.LEASE_DURATION_MILLIS

            assertNull(VaultExternalCopyStore.find(context, lease.uri))
            assertFalse(file.exists())
            lease.cleanup()
            assertTrue(root.listFiles().orEmpty().isEmpty())
        }
}
