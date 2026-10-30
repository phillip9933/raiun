package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.util.UUID

/** Actual Android directory syscalls and rclone authentication; injected errors are not power-loss tests. */
@RunWith(AndroidJUnit4::class)
class VaultOfflineDurabilityAndroidTest {
    @Test fun nativeDirectoryFsyncStopsAtNoBackupBoundaryAndRefusesOutsideMutation() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir, "offline-durability-native-${UUID.randomUUID()}")
        val indexes = File(root, "account/vault/indexes")
        val outside = File(context.filesDir, "offline-durability-outside-${UUID.randomUUID()}")
        assertTrue(indexes.mkdirs())
        assertTrue(outside.mkdirs())
        val sentinel = File(outside, "preserve.txt").apply { writeText("preserve") }
        val synced = mutableListOf<File>()
        val durability =
            OfflineDurability(context.noBackupFilesDir) {
                synced += it.canonicalFile
                fsyncOfflineDirectory(it)
            }
        try {
            durability.syncParents(indexes)
            assertEquals(
                listOf(indexes, indexes.parentFile, indexes.parentFile!!.parentFile, root, context.noBackupFilesDir)
                    .map { it!!.canonicalFile },
                synced,
            )
            assertFalse(synced.contains(context.noBackupFilesDir.parentFile!!.canonicalFile))
            val metadata = File(indexes.parentFile, "root.enc")
            durability.writeAtomic(metadata, byteArrayOf(1, 2, 3))
            assertEquals(listOf<Byte>(1, 2, 3), metadata.readBytes().toList())
            durability.deleteAtomic(metadata)
            assertFalse(metadata.exists())
            assertThrows(IOException::class.java) {
                durability.writeAtomic(File(outside, "new.enc"), byteArrayOf(1))
            }
            assertThrows(IOException::class.java) { durability.deleteAtomic(sentinel) }
            assertThrows(Exception::class.java) { VaultOfflineOwnership(root, durability).deleteOwnedTree(outside) }
            assertEquals(
                setOf(sentinel.name),
                outside
                    .listFiles()
                    .orEmpty()
                    .map(File::getName)
                    .toSet(),
            )
            assertEquals("preserve", sentinel.readText())
        } finally {
            root.deleteRecursively()
            outside.deleteRecursively()
        }
    }

    @Test fun nativePreparedAndCommittedReceiptsRecoverAfterAmbiguousSyncWithoutAnyTransferRow() {
        for (committed in listOf(false, true)) {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val root = File(context.noBackupFilesDir, "offline-receipt-native-${UUID.randomUUID()}")
            val material = ByteArray(80) { it.toByte() }
            val account =
                AccountEntity("native-${UUID.randomUUID()}", "https://example.test/", "u", "User", "BASIC", false)
            val identity = VaultIdentity(account.id, account.serverUrl, "drive", "vault-id")
            val location =
                VaultLocation(
                    account.id,
                    "Secret.vault",
                    VaultLocationKind.FOLDER_VAULT,
                    "drive",
                    "vault-id",
                    "root-id",
                    account.serverUrl,
                    "https://example.test/dav/files/",
                    "Secret.vault",
                    true,
                )
            var inject = false
            var injected = false
            var transferAuthorityCalls = 0
            val durability =
                OfflineDurability(context.noBackupFilesDir) { directory ->
                    if (inject && !injected) {
                        val manifest = root.walkTopDown().single { it.name == "manifest.enc" }
                        if (VaultOfflinePublicationJournal.read(manifest.parentFile!!)?.localCommitted == true) {
                            injected = true
                            throw IOException("synthetic receipt-directory fsync failure")
                        }
                    }
                    fsyncOfflineDirectory(directory)
                }

            fun store() =
                VaultOfflineStore(
                    root,
                    { account },
                    { { true } },
                    EndpointPolicy(true),
                    { RcloneVaultCipher.fromKeyMaterial(it).offlineEngine() },
                    publicationAccepted = { _, _ ->
                        transferAuthorityCalls++
                        false
                    },
                    durability = durability,
                )
            try {
                val offline = store()
                pin(offline, identity, location, material, "old")
                val manifest = root.walkTopDown().single { it.name == "manifest.enc" }
                val previous = manifest.readBytes()
                val previousIndex = indexFile(manifest.parentFile!!, previous)
                val oldBlob = File(manifest.parentFile, "blobs").listFiles().orEmpty().single()
                inject = true
                assertThrows(Exception::class.java) { pin(offline, identity, location, material, "new") }
                assertTrue(injected)
                val next = manifest.readBytes()
                assertFalse(previous.contentEquals(next))
                assertTrue(previousIndex.isFile)
                assertTrue(indexFile(manifest.parentFile!!, next).isFile)
                assertTrue(oldBlob.isFile)
                assertEquals(2, File(manifest.parentFile, "blobs").listFiles().orEmpty().size)
                val receipt = requireNotNull(VaultOfflinePublicationJournal.read(manifest.parentFile!!))
                assertEquals(true, receipt.localCommitted)
                inject = false
                if (!committed) {
                    // Recreate the prior durable PREPARED state, as a deterministic recovery fixture.
                    receipt.copy(localCommitted = false).write(manifest.parentFile!!, durability)
                }
                runBlocking {
                    store().openWithKeyMaterial(account.id, location, material)!!.use { session ->
                        val output = ByteArrayOutputStream()
                        session.download(session.list().single(), output)
                        assertEquals(if (committed) "new" else "old", output.toString(Charsets.UTF_8.name()))
                    }
                }
                assertEquals(0, transferAuthorityCalls)
                assertEquals(null, VaultOfflinePublicationJournal.read(manifest.parentFile!!))
                assertEquals(!committed, previousIndex.exists())
                assertEquals(committed, indexFile(manifest.parentFile!!, next).exists())
                assertEquals(1, File(manifest.parentFile, "blobs").listFiles().orEmpty().size)
            } finally {
                material.fill(0)
                root.deleteRecursively()
            }
        }
    }

    private fun pin(
        store: VaultOfflineStore,
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
        text: String,
    ) = runBlocking {
        val encrypted = ByteArrayOutputStream()
        val raw =
            RcloneVaultCipher.fromKeyMaterial(material).use { cipher ->
                cipher.encryptContent(text.byteInputStream(), encrypted, 1024)
                cipher.encryptName("payload")
            }
        val bytes = encrypted.toByteArray()
        val entry =
            VaultFolder(
                "payload",
                "payload",
                raw,
                "payload",
                "${location.vaultPath}/$raw",
                false,
                bytes.size.toLong(),
                "\"$text\"",
            )
        store.pinFile(identity, location, entry, material) { it.write(bytes) }
    }

    private fun indexFile(
        directory: File,
        root: ByteArray,
    ): File = File(directory, "indexes/${VaultOfflineIndex.generation(root)}.db")
}
