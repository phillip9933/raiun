package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.VaultDavEntry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class VaultDownloadStoreTest {
    private val root = Files.createTempDirectory("pending-ciphertext").toFile()
    private val store = VaultDownloadStore(root)
    private val location =
        VaultLocation(
            "account",
            "Private title",
            VaultLocationKind.FOLDER_VAULT,
            "drive",
            "vault-id",
            "root",
            "https://example.test/",
            "https://example.test/dav/",
            "public.vault",
            true,
        )
    private val source =
        VaultDavEntry(
            "source",
            "public.vault/cipher",
            "cipher",
            false,
            96,
            "\"version\"",
            "https://example.test/dav/public.vault/cipher",
        )

    @After fun clean() {
        root.deleteRecursively()
    }

    @Test fun committedCaptureSurvivesProcessRestartWithoutPlaintextTitle() {
        val job = store.create(location, source, vaultProofDigest("proof"))
        store.partial(job).writeBytes(ByteArray(20))
        assertTrue(store.finishPrepared(job.id) { true })
        val restarted = VaultDownloadStore(root)
        assertEquals(job, restarted.read(job.id))
        assertEquals(20L, restarted.partial(job).length())
        assertFalse(File(root, "${job.id}/manifest").readText().contains("Private title"))
    }

    @Test fun accountRemovalDuringAdmissionDeletesStageEvenIfRoomStillHasRow() {
        val job = store.create(location, source, null)
        store.forgetAccount(location.accountId)
        assertFalse(store.finishPrepared(job.id) { true })
        assertFalse(File(root, job.id).exists())
    }

    @Test fun reconciliationChecksLiveAdmissionAndCancellationDropsOnlyRawBytes() {
        val job = store.create(location, source, null)
        store.reconcile { false }
        store.partial(job).writeBytes(ByteArray(20))
        assertTrue(store.finishPrepared(job.id) { true })
        store.reconcile { it == job.id }
        store.beginAttempt(job.id, location.accountId).use { attempt ->
            store.discardPayload(job.id)
            assertEquals(job, store.read(job.id))
            assertFalse(store.partial(job).exists())
            assertFalse(attempt.isActive)
        }
        assertEquals(0, VaultDownloadStore.activeAttemptCount())
        store.beginAttempt(job.id, location.accountId).use { retried -> assertTrue(retried.isActive) }
    }

    @Test fun cancellationAndAccountRemovalKeepOnlyLiveAttemptTokens() {
        repeat(100) {
            val job = store.create(location, source, null)
            assertTrue(store.finishPrepared(job.id) { true })
            store.beginAttempt(job.id, location.accountId).use { attempt ->
                store.discardPayload(job.id)
                assertFalse(attempt.isActive)
                store.delete(job.id)
            }
        }
        assertEquals(0, VaultDownloadStore.activeAttemptCount())
        val job = store.create(location, source, null)
        assertTrue(store.finishPrepared(job.id) { true })
        store.beginAttempt(job.id, location.accountId).use { attempt ->
            store.forgetAccount(location.accountId)
            assertFalse(attempt.isActive)
        }
        assertEquals(0, VaultDownloadStore.activeAttemptCount())
    }

    @Test fun traversalAndWeakVersionAreRejectedBeforeCapture() {
        assertThrows(IllegalArgumentException::class.java) {
            store.create(location, source.copy(relativePath = "public.vault/../cipher"), null)
        }
        assertThrows(IllegalArgumentException::class.java) {
            store.create(location, source.copy(strongETag = "W/\"version\""), null)
        }
        assertTrue(root.listFiles().orEmpty().isEmpty())
    }

    @Test fun strictRemovalRetainsActiveAttemptUntilClosedAndPreservesOtherAccount() {
        val job = store.create(location, source, null)
        assertTrue(store.finishPrepared(job.id) { true })
        val other = store.create(location.copy(accountId = "other"), source, null)
        assertTrue(store.finishPrepared(other.id) { true })
        store.beginAttempt(job.id, location.accountId).use { attempt ->
            assertThrows(IllegalStateException::class.java) { store.forgetAccountForRemoval(location.accountId) }
            assertFalse(attempt.isActive)
            assertTrue(File(root, job.id).exists())
        }
        VaultDownloadStore(root).forgetAccountForRemoval(location.accountId)
        assertFalse(File(root, job.id).exists())
        assertEquals(other, store.read(other.id))
    }

    @Test fun strictRemovalRevokesPreparedHandoffButCannotAcknowledgeItEarly() {
        val job = store.create(location, source, null)
        assertThrows(IllegalStateException::class.java) { store.forgetAccountForRemoval(location.accountId) }
        assertTrue(File(root, job.id).exists())
        assertFalse(store.finishPrepared(job.id) { true })
        store.forgetAccountForRemoval(location.accountId)
        assertFalse(File(root, job.id).exists())
    }

    @Test fun strictRemovalPreservesCorruptUnknownOwnerAndRejectsUnreadableInventory() {
        val job = store.create(location.copy(accountId = "other"), source, null)
        assertTrue(store.finishPrepared(job.id) { true })
        File(root, "${job.id}/manifest").writeBytes(byteArrayOf(0))
        assertThrows(Exception::class.java) { VaultDownloadStore(root).forgetAccountForRemoval(location.accountId) }
        assertTrue(File(root, job.id).exists())
        val unavailable =
            object : File(root, "unreadable") {
                override fun listFiles(): Array<File>? = null
            }
        assertTrue(unavailable.mkdir())
        assertThrows(IllegalStateException::class.java) { VaultDownloadStore(unavailable).forgetAccountForRemoval("a") }
    }
}
