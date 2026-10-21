package eu.opencloud.android.next.core.sync

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class VaultUploadStoreTest {
    private val root = Files.createTempDirectory("vault-upload-test").toFile()
    private val store = VaultUploadStore(root)
    private val location =
        VaultLocation(
            "account",
            "private title",
            VaultLocationKind.FOLDER_VAULT,
            "drive",
            "vault-id",
            "source-id",
            "https://example.test/",
            "https://example.test/dav/",
            "public.vault",
            true,
        )
    private val ciphertext = ByteArray(96) { (it + 7).toByte() }

    @After fun clean() {
        root.deleteRecursively()
    }

    @Test fun committedPayloadSurvivesNewStoreWithoutPlaintextNamesOrKeys() {
        val job = prepare()
        check(store.finishPrepared(job.id) { true })
        val recovered = VaultUploadStore(root).read(job.id)
        assertEquals(job, recovered)
        assertEquals("", recovered.location.title)
        assertFalse(File(root, "${job.id}/manifest").readBytes().toString(Charsets.UTF_8).contains("private title"))
    }

    @Test fun modifiedOrShortPayloadIsRejectedBeforeNetworkUse() {
        val job = prepare()
        check(store.finishPrepared(job.id) { true })
        val payload = File(root, "${job.id}/content")
        payload.writeBytes(ciphertext.copyOf().also { it[40] = 0 })
        assertThrows(eu.opencloud.android.next.core.network.OpenCloudException::class.java) { store.read(job.id) }
        payload.writeBytes(ciphertext.copyOf(40))
        assertThrows(eu.opencloud.android.next.core.network.OpenCloudException::class.java) { store.read(job.id) }
    }

    @Test fun rejectsTraversalAndDestinationsOutsideCapturedVault() {
        assertThrows(IllegalArgumentException::class.java) { store.read("../outside") }
        assertThrows(IllegalArgumentException::class.java) { prepare("public.vault/../ordinary") }
        assertThrows(IllegalArgumentException::class.java) { prepare("ordinary/enc-name") }
        assertTrue(root.listFiles().orEmpty().isEmpty())
    }

    @Test fun reconciliationCannotDeletePreparedPayloadBeforeRoomCommit() {
        val job = prepare()
        store.reconcile { false }
        assertEquals(job, store.read(job.id))
        check(store.finishPrepared(job.id) { true })
        store.reconcile { it == job.id }
        assertEquals(job, store.read(job.id))
        store.reconcile { false }
        assertFalse(File(root, job.id).exists())
    }

    @Test fun interruptedEncryptionCleansPartialOutputAndReconcileDoesNotBlockOnEncryption() {
        val started = CountDownLatch(1)
        val finish = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val future =
                executor.submit<VaultUploadJob> {
                    store.prepare(location, "public.vault/enc-name", null, vaultProofDigest("public proof")) {
                        it.write(ciphertext)
                        started.countDown()
                        check(finish.await(5, TimeUnit.SECONDS))
                        error("synthetic cancellation")
                    }
                }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            store.reconcile { false }
            assertEquals(1, root.listFiles().orEmpty().size)
            finish.countDown()
            assertThrows(java.util.concurrent.ExecutionException::class.java) { future.get(5, TimeUnit.SECONDS) }
            assertTrue(root.listFiles().orEmpty().isEmpty())
        } finally {
            finish.countDown()
            executor.shutdownNow()
        }
    }

    @Test fun accountCleanupDoesNotTouchAnotherAccountAndRemovesIncompleteJobs() {
        val job = prepare()
        check(store.finishPrepared(job.id) { true })
        store.forgetAccount("other-account")
        assertEquals(job, store.read(job.id))
        store.forgetAccount("account")
        assertFalse(File(root, job.id).exists())
    }

    @Test fun cleanupNeverFollowsAnInjectedSymlink() {
        val job = prepare()
        val external = Files.createTempDirectory("vault-upload-external").toFile()
        try {
            val preserved = File(external, "preserved")
            preserved.writeText("synthetic external material")
            Files.createSymbolicLink(File(root, "${job.id}/injected-link").toPath(), external.toPath())
            store.delete(job.id)
            assertTrue(preserved.isFile)
        } finally {
            external.deleteRecursively()
        }
    }

    @Test fun removalDuringPreparedHandoffCannotLeaveCiphertextAfterCleanup() {
        val job = prepare()
        store.forgetAccount(location.accountId)
        assertTrue(File(root, job.id).exists())
        assertFalse(store.finishPrepared(job.id) { true })
        assertFalse(File(root, job.id).exists())
    }

    @Test fun committedJobFinalizationPreservesCiphertextWithoutAnOldCredentialLease() {
        val job = prepare()
        assertTrue(store.finishPrepared(job.id) { true })
        assertEquals(job, store.read(job.id))
    }

    @Test fun authoritativeCleanupRetainsJobsAdmittedAfterAnEarlierEnumeration() {
        val oldIds = store.ids()
        val job = prepare()
        assertTrue(oldIds.isEmpty())
        assertTrue(store.finishPrepared(job.id) { true })
        store.reconcile { it == job.id }
        assertEquals(job, store.read(job.id))
    }

    private fun prepare(destination: String = "public.vault/enc-name") =
        store.prepare(location, destination, null, vaultProofDigest("public proof")) { it.write(ciphertext) }
}
