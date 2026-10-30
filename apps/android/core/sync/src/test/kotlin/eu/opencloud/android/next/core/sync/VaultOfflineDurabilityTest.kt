package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.UUID

/** Deterministic directory-sync failures; these do not simulate physical power loss. */
@RunWith(RobolectricTestRunner::class)
class VaultOfflineDurabilityTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun rejectedPublicationRestoresBackupOnlyCatalogAndExactPreviousSnapshot() =
        fixture { state ->
            val store = state.store()
            state.pin(store, "old")
            val manifest = state.manifest()
            val previous = manifest.readBytes()
            val catalog = File(manifest.parentFile, "root.json")
            val catalogBytes = catalog.readBytes()
            val oldIndex = state.index(previous).readBytes()
            val oldBlob = state.blobs().single()
            val oldBlobBytes = oldBlob.readBytes()
            assertTrue(catalog.renameTo(File(catalog.path + ".bak")))
            assertFalse(catalog.exists())
            state.afterPublication = { throw IOException("synthetic rejection before local commit") }

            assertThrows(Exception::class.java) { state.pin(store, "new") }
            assertArrayEquals(previous, manifest.readBytes())
            assertArrayEquals(catalogBytes, catalog.readBytes())
            assertArrayEquals(oldIndex, state.index(previous).readBytes())
            assertArrayEquals(oldBlobBytes, oldBlob.readBytes())
            assertEquals(1, state.blobs().size)
            assertEquals(null, VaultOfflinePublicationJournal.read(manifest.parentFile!!))
            state.afterPublication = {}
            assertEquals("old", state.read(store))
        }

    @Test fun generationDirectorySyncFailureBeforePublicationLeavesOldMetadataAndContentUntouched() =
        fixture { state ->
            val store = state.store()
            state.pin(store, "old")
            val manifest = state.manifest()
            val previous = manifest.readBytes()
            val catalog = File(manifest.parentFile, "root.json").readBytes()
            val oldBlob = state.blobs().single()
            val oldBlobBytes = oldBlob.readBytes()
            var injected = false
            state.sync = { directory ->
                if (!injected && directory.name == "indexes") {
                    injected = true
                    throw IOException("synthetic generation directory sync failure")
                }
            }

            assertThrows(Exception::class.java) { state.pin(store, "new") }
            assertTrue(injected)
            assertArrayEquals(previous, manifest.readBytes())
            assertArrayEquals(catalog, File(manifest.parentFile, "root.json").readBytes())
            assertArrayEquals(oldBlobBytes, oldBlob.readBytes())
            assertEquals(1, state.blobs().size)
            assertEquals(null, VaultOfflinePublicationJournal.read(manifest.parentFile!!))
            state.sync = {}
            assertEquals("old", state.read(store))
        }

    @Test fun ambiguousLocalCommitSyncRetainsBothSidesAndRecoversWithoutATransferAuthority() =
        fixture { state ->
            val store = state.store()
            state.pin(store, "old")
            val manifest = state.manifest()
            val previous = manifest.readBytes()
            val previousIndex = state.index(previous)
            val oldBlob = state.blobs().single()
            var injected = false
            state.sync = {
                if (!injected && VaultOfflinePublicationJournal.read(manifest.parentFile!!)?.localCommitted == true) {
                    injected = true
                    throw IOException("synthetic ambiguous committed receipt directory sync")
                }
            }

            assertThrows(Exception::class.java) { state.pin(store, "new") }
            assertTrue(injected)
            val pending = requireNotNull(VaultOfflinePublicationJournal.read(manifest.parentFile!!))
            assertEquals(true, pending.localCommitted)
            assertFalse(previous.contentEquals(manifest.readBytes()))
            assertTrue(previousIndex.isFile)
            assertTrue(state.index(manifest.readBytes()).isFile)
            assertTrue(oldBlob.isFile)
            assertEquals(2, state.blobs().size)
            assertEquals(0, state.transferAuthorityCalls)

            state.sync = {}
            assertEquals("new", state.read(state.store()))
            assertEquals(0, state.transferAuthorityCalls)
            assertEquals(null, VaultOfflinePublicationJournal.read(manifest.parentFile!!))
            assertFalse(previousIndex.exists())
            assertFalse(oldBlob.exists())
            assertEquals(1, state.blobs().size)
        }

    @Test fun confinementRejectsOutsideWritesDeletesAndRootAccountOrVaultSymlinksBeforeMutation() =
        fixture { state ->
            val outside = temporary.newFolder("outside")
            val sentinel = File(outside, "preserve.txt").apply { writeText("untouched") }
            val owned = VaultOfflineOwnership(state.root, state.durability)
            assertThrows(IOException::class.java) {
                state.durability.writeAtomic(File(outside, "new-root.enc"), byteArrayOf(1))
            }
            assertThrows(IOException::class.java) { state.durability.deleteAtomic(sentinel) }
            assertThrows(Exception::class.java) { owned.deleteOwnedTree(outside) }
            assertThrows(Exception::class.java) {
                VaultOfflineIndex.prepare(
                    outside,
                    state.identity,
                    state.location,
                    state.material,
                    LegacyOfflineManifest(emptyMap()),
                    durability = state.durability,
                )
            }
            assertEquals(
                setOf(sentinel.name),
                outside
                    .listFiles()
                    .orEmpty()
                    .map(File::getName)
                    .toSet(),
            )
            assertEquals("untouched", sentinel.readText())

            for (level in listOf("root", "account", "vault")) {
                val root = File(state.boundary, "symlink-$level")
                val owner = VaultOfflineOwnership(root, state.durability)
                val link =
                    when (level) {
                        "root" -> root
                        "account" -> {
                            assertTrue(root.mkdirs())
                            owner.accountDirectory(state.account.id)
                        }
                        else -> {
                            assertTrue(owner.accountDirectory(state.account.id).mkdirs())
                            owner.vaultDirectory(state.identity)
                        }
                    }
                Files.createSymbolicLink(link.toPath(), outside.toPath())
                try {
                    assertThrows(Exception::class.java) {
                        runBlocking {
                            state.store(root).pinDirectory(
                                state.identity,
                                state.location,
                                state.location.vaultPath,
                                state.material,
                            )
                        }
                    }
                    assertEquals(
                        setOf(sentinel.name),
                        outside
                            .listFiles()
                            .orEmpty()
                            .map(File::getName)
                            .toSet(),
                    )
                    assertEquals("untouched", sentinel.readText())
                    assertTrue(Files.isSymbolicLink(link.toPath()))
                } finally {
                    Files.deleteIfExists(link.toPath())
                }
            }
        }

    private fun fixture(block: (Fixture) -> Unit) {
        val state = Fixture(temporary.newFolder())
        try {
            block(state)
        } finally {
            state.material.fill(0)
        }
    }

    private class Fixture(
        val boundary: File,
    ) {
        val root = File(boundary, "vault-offline")
        val account =
            AccountEntity("durability-${UUID.randomUUID()}", "https://example.test/", "u", "User", "BASIC", false)
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
        val material = ByteArray(80) { it.toByte() }
        var sync: (File) -> Unit = {}
        var afterPublication: () -> Unit = {}
        var transferAuthorityCalls = 0
        val durability = jvmOfflineDurability(boundary) { sync(it) }

        fun store(directory: File = root): VaultOfflineStore =
            VaultOfflineStore(
                directory,
                { account },
                { { true } },
                EndpointPolicy(true),
                { VaultOfflineTestCipher() },
                afterPublication = { afterPublication() },
                publicationAccepted = { _, _ ->
                    transferAuthorityCalls++
                    false
                },
                durability = durability,
            )

        fun pin(
            store: VaultOfflineStore,
            value: String,
        ) = runBlocking {
            val bytes = ByteArray(32) { 7 } + value.toByteArray() + ByteArray(16) { 9 }
            val entry =
                VaultFolder(
                    "payload",
                    "payload",
                    "payload",
                    "payload",
                    "Secret.vault/payload",
                    false,
                    bytes.size.toLong(),
                    "\"$value\"",
                )
            store.pinFile(identity, location, entry, material) { it.write(bytes) }
        }

        fun read(store: VaultOfflineStore): String =
            runBlocking {
                store.openWithKeyMaterial(account.id, location, material)!!.use { session ->
                    val output = ByteArrayOutputStream()
                    session.download(session.list().single(), output)
                    output.toString(Charsets.UTF_8.name())
                }
            }

        fun manifest(): File = root.walkTopDown().single { it.name == "manifest.enc" }

        fun index(bytes: ByteArray): File =
            File(manifest().parentFile, "indexes/${VaultOfflineIndex.generation(bytes)}.db")

        fun blobs(): List<File> = File(manifest().parentFile, "blobs").listFiles().orEmpty().toList()
    }
}
