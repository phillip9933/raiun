package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
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
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
class VaultOfflineMigrationTest {
    @get:Rule val temporary = TemporaryFolder()
    private val account = AccountEntity("legacy-account", "https://example.test/", "user", "User", "BASIC", false)
    private val location =
        VaultLocation(
            account.id,
            "Secret.vault",
            VaultLocationKind.FOLDER_VAULT,
            "drive",
            "vault-id",
            "source-root",
            account.serverUrl,
            "https://example.test/dav/files/",
            "Secret.vault",
            true,
        )
    private val identity = VaultIdentity(account.id, account.serverUrl, "drive", "vault-id")
    private val material = ByteArray(80) { it.toByte() }

    @Test fun authenticatedLegacySnapshotImportsWithoutReencryptingExistingCiphertextOrChangingIdentity() =
        runBlocking {
            val fixture = fixture()
            val legacy = fixture.manifest.readBytes()
            fixture.store.openWithKeyMaterial(account.id, location, material)!!.use { session ->
                assertEquals(identity, session.identity)
                val output = ByteArrayOutputStream()
                session.download(session.list().single(), output)
                assertEquals("legacy content", output.toString(Charsets.UTF_8.name()))
            }
            // A read preserves legacy bytes; the first successful mutation imports into the new index.
            assertArrayEquals(legacy, fixture.manifest.readBytes())
            fixture.store.pinDirectory(identity, location, "Secret.vault/new-directory", material)
            assertTrue(VaultOfflineIndex.recognizes(fixture.manifest.readBytes()))
            assertArrayEquals(fixture.ciphertext, fixture.blob.readBytes())
            assertEquals(
                fixture.blob.name,
                readOfflineManifest(fixture.manifest, identity, location, material).use {
                    it.find("Secret.vault/cipher")!!.blobId
                },
            )
            fixture.store.openWithKeyMaterial(account.id, location, material)!!.use {
                assertEquals(2, it.list().size)
            }
        }

    @Test fun failedLegacyImportLeavesOriginalManifestCiphertextAndReadableSnapshot() =
        runBlocking {
            val fixture = fixture()
            val legacy = fixture.manifest.readBytes()
            val rejecting =
                store(fixture.root, beforePublication = { throw IOException("synthetic publication refusal") })
            assertThrows(IOException::class.java) {
                runBlocking { rejecting.pinDirectory(identity, location, "Secret.vault/new-directory", material) }
            }
            assertArrayEquals(legacy, fixture.manifest.readBytes())
            assertArrayEquals(fixture.ciphertext, fixture.blob.readBytes())
            assertFalse(File(fixture.manifest.parentFile, "indexes").listFiles().orEmpty().any { it.extension == "db" })
            fixture.store.openWithKeyMaterial(account.id, location, material)!!.use { assertEquals(1, it.list().size) }
        }

    @Test fun versionOnePublicationJournalStillRestoresLegacyRootBeforeAnyIndexImport() =
        runBlocking {
            val fixture = fixture()
            val previous = fixture.manifest.readBytes()
            val next = prepare(fixture, "Secret.vault/new-directory")
            val journal = journal(fixture, previous, null)
            journal.write(fixture.manifest.parentFile!!, jvmOfflineDurability(fixture.root))
            assertEquals(null, VaultOfflinePublicationJournal.read(fixture.manifest.parentFile!!)!!.nextManifestDigest)
            fixture.manifest.writeBytes(next)
            fixture.store.recoverPendingPublications(account.id)
            assertArrayEquals(previous, fixture.manifest.readBytes())
            assertFalse(File(fixture.manifest.parentFile, "publication.pending").exists())
            fixture.store.openWithKeyMaterial(account.id, location, material)!!.use { assertEquals(1, it.list().size) }
            assertArrayEquals(fixture.ciphertext, fixture.blob.readBytes())
        }

    @Test fun newJournalRestoresOnlyItsCapturedPreviousOrNextRootAndNeverAnUnrelatedGeneration() =
        runBlocking {
            val fixture = fixture()
            val previous = fixture.manifest.readBytes()
            val next = prepare(fixture, "Secret.vault/new-directory")
            val unrelated = prepare(fixture, "Secret.vault/different-directory")
            val journal = journal(fixture, previous, digest(next))
            journal.write(fixture.manifest.parentFile!!, jvmOfflineDurability(fixture.root))
            fixture.manifest.writeBytes(next)
            journal.restore(fixture.manifest.parentFile!!, jvmOfflineDurability(fixture.root))
            assertArrayEquals(previous, fixture.manifest.readBytes())
            fixture.manifest.writeBytes(unrelated)
            assertThrows(OpenCloudException::class.java) {
                journal.restore(fixture.manifest.parentFile!!, jvmOfflineDurability(fixture.root))
            }
            assertThrows(
                OpenCloudException::class.java,
            ) {
                journal.finish(
                    fixture.manifest.parentFile!!,
                    accepted = true,
                    durability = jvmOfflineDurability(fixture.root),
                )
            }
            assertArrayEquals(unrelated, fixture.manifest.readBytes())
            assertTrue(File(fixture.manifest.parentFile, "publication.pending").exists())
            assertArrayEquals(fixture.ciphertext, fixture.blob.readBytes())
        }

    @Test fun localPreparedReceiptRollsBackAndCommittedReceiptKeepsNextRootWithoutTransferAuthority() =
        runBlocking {
            val fixture = fixture()
            val previous = fixture.manifest.readBytes()
            val next = prepare(fixture, "Secret.vault/new-directory")
            val prepared = journal(fixture, previous, digest(next)).copy(localCommitted = false)
            prepared.write(fixture.manifest.parentFile!!, jvmOfflineDurability(fixture.root))
            fixture.manifest.writeBytes(next)
            fixture.store.recoverPendingPublications(account.id)
            assertArrayEquals(previous, fixture.manifest.readBytes())
            prepared.write(fixture.manifest.parentFile!!, jvmOfflineDurability(fixture.root))
            fixture.manifest.writeBytes(next)
            prepared.commitLocal(fixture.manifest.parentFile!!, jvmOfflineDurability(fixture.root))
            assertEquals(true, VaultOfflinePublicationJournal.read(fixture.manifest.parentFile!!)!!.localCommitted)
            // This Store's transfer callback always returns false: only the durable local receipt accepts.
            fixture.store.recoverPendingPublications(account.id)
            assertArrayEquals(next, fixture.manifest.readBytes())
            assertFalse(File(fixture.manifest.parentFile, "publication.pending").exists())
            fixture.store.openWithKeyMaterial(account.id, location, material)!!.use { assertEquals(2, it.list().size) }
        }

    @Test fun legacyReaderLeaseRetainsItsCiphertextAcrossImportAndPruneUntilClose() =
        runBlocking {
            val fixture = fixture()
            val legacySession = fixture.store.openWithKeyMaterial(account.id, location, material)!!
            try {
                val issued = legacySession.list().single()
                fixture.store.pinDirectory(identity, location, "Secret.vault/new-directory", material)
                fixture.store.pruneSubtree(
                    identity,
                    location,
                    "Secret.vault",
                    setOf("Secret.vault/new-directory"),
                    material,
                )
                fixture.store.openWithKeyMaterial(account.id, location, material)!!.close()
                assertTrue(fixture.blob.exists())
                assertThrows(
                    OpenCloudException::class.java,
                ) { runBlocking { legacySession.download(issued, ByteArrayOutputStream()) } }
            } finally {
                legacySession.close()
            }
            fixture.store.openWithKeyMaterial(account.id, location, material)!!.close()
            assertFalse(fixture.blob.exists())
        }

    @Test fun strictMetadataCodecRejectsUnpairedSurrogatesAndMalformedUtf8WithoutChangingValidUnicode() {
        val valid = OfflineEntry("Secret.vault/cipher", "cipher", "opaque-\uD83D\uDE00", true, 0L, null, null, null)
        val encoded = VaultOfflineIndexCodec.encodeEntry(valid)
        assertEquals(valid, VaultOfflineIndexCodec.decodeEntry(encoded, location))
        assertThrows(OpenCloudException::class.java) { VaultOfflineIndexCodec.encodeEntry(valid.copy(id = "\uD800")) }
        assertThrows(
            OpenCloudException::class.java,
        ) { VaultOfflineIndexCodec.text(byteArrayOf(0xc0.toByte(), 0xaf.toByte())) }
        val escaped =
            String(
                encoded,
                Charsets.UTF_8,
            ).replace("opaque-\uD83D\uDE00", "\\ud800").toByteArray(Charsets.UTF_8)
        assertThrows(OpenCloudException::class.java) { VaultOfflineIndexCodec.decodeEntry(escaped, location) }
    }

    @Test fun absentRevokedAccountPreparationDoesNotCreateOrSynchronizeMissingOfflineRoot() {
        val boundary = temporary.newFolder()
        val missingRoot = File(boundary, "not-created-offline-root")
        val synchronized = mutableListOf<File>()
        val ownership = VaultOfflineOwnership(missingRoot, jvmOfflineDurability(boundary) { synchronized += it })
        val absentIdentity = VaultIdentity(UUID.randomUUID().toString(), account.serverUrl, "drive", "vault-id")
        VaultOfflineRevocations.revokeAccount(absentIdentity.accountId)
        VaultOfflineRevocations.finishAccountRevoke(absentIdentity.accountId)
        ownership.prepareForPin(absentIdentity)
        assertTrue(synchronized.isEmpty())
        assertFalse(missingRoot.exists())
    }

    @Test fun actualLegacyAndGenerationRootWrongMaterialIsUnlockFailureButRowTamperIsIntegrityFailure() =
        runBlocking {
            val fixture = fixture()
            val wrong = material.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
            try {
                val legacyFailure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { fixture.store.openWithKeyMaterial(account.id, location, wrong) }
                    }
                assertEquals(OpenCloudError.EncryptedUnlockFailed, legacyFailure.error)
                fixture.store.pinDirectory(identity, location, "Secret.vault/new-directory", material)
                val generationFailure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { fixture.store.openWithKeyMaterial(account.id, location, wrong) }
                    }
                assertEquals(OpenCloudError.EncryptedUnlockFailed, generationFailure.error)
                val root = fixture.manifest.readBytes()
                val generation = requireNotNull(VaultOfflineIndex.generation(root))
                val index = File(fixture.manifest.parentFile, "indexes/$generation.db")
                SQLiteDatabase.openDatabase(index.path, null, SQLiteDatabase.OPEN_READWRITE).use {
                    it.execSQL("UPDATE chunks SET payload = zeroblob(length(payload)) WHERE seq = 0 AND part = 0")
                }
                val corruption =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { fixture.store.openWithKeyMaterial(account.id, location, material) }
                    }
                assertEquals(OpenCloudError.DownloadIntegrity, corruption.error)
                assertArrayEquals(root, fixture.manifest.readBytes())
            } finally {
                wrong.fill(0)
            }
        }

    private suspend fun fixture(): Fixture {
        val root = temporary.newFolder()
        val store = store(root)
        val ciphertext = ByteArray(32) { 7 } + "legacy content".toByteArray() + ByteArray(16) { 9 }
        val entry =
            VaultFolder(
                "file-id",
                "cipher",
                "cipher",
                "cipher",
                "Secret.vault/cipher",
                false,
                ciphertext.size.toLong(),
                "\"tag\"",
            )
        store.pinFile(identity, location, entry, material) { it.write(ciphertext) }
        val manifest = root.walkTopDown().single { it.name == "manifest.enc" }
        val saved = readOfflineManifest(manifest, identity, location, material).use { it.find(entry.encryptedPath)!! }
        val blob = File(File(manifest.parentFile, "blobs"), saved.blobId!!)
        val plain =
            JSONObject()
                .put("version", 1)
                .put("location", encodeLocation(location))
                .put(
                    "entries",
                    JSONArray().put(
                        JSONObject()
                            .put(
                                "path",
                                saved.encryptedPath,
                            ).put("name", saved.rawName)
                            .put("id", saved.id)
                            .put("folder", false)
                            .put("size", saved.size)
                            .put("etag", saved.etag)
                            .put("blob", saved.blobId)
                            .put("digest", saved.digest),
                    ),
                ).toString()
                .toByteArray()
        val key = deriveManifestKey(material, identity)
        val nonce = ByteArray(12).also(java.security.SecureRandom()::nextBytes)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            cipher.updateAAD(identityBytes(identity))
            manifest.writeBytes("RVO1".toByteArray() + nonce + cipher.doFinal(plain))
        } finally {
            key.fill(0)
            nonce.fill(0)
            plain.fill(0)
        }
        // This is synthetic test-owned data, making a genuine legacy-only disk fixture.
        File(manifest.parentFile, "indexes").deleteRecursively()
        return Fixture(root, store, manifest, blob, ciphertext)
    }

    private fun store(
        root: File,
        beforePublication: () -> Unit = {},
    ) = VaultOfflineStore(
        root,
        { account },
        { { true } },
        EndpointPolicy(true),
        { VaultOfflineTestCipher() },
        beforePublication = beforePublication,
        durability = jvmOfflineDurability(root),
    )

    private fun prepare(
        fixture: Fixture,
        path: String,
    ): ByteArray =
        readOfflineManifest(fixture.manifest, identity, location, material).use {
            VaultOfflineIndex.prepare(
                fixture.manifest.parentFile!!,
                identity,
                location,
                material,
                it.withDirectoryAndAncestors(location, path),
                durability = jvmOfflineDurability(fixture.root),
            )
        }

    private fun journal(
        fixture: Fixture,
        previous: ByteArray,
        nextDigest: String?,
    ) = VaultOfflinePublicationJournal(
        UUID.randomUUID().toString(),
        UUID.randomUUID().toString(),
        fixture.blob.name,
        encodeLocation(location).toByteArray(),
        previous,
        File(fixture.manifest.parentFile, "root.json").readBytes(),
        nextDigest,
    )

    private fun digest(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
            "%02x".format(it)
        }

    private data class Fixture(
        val root: File,
        val store: VaultOfflineStore,
        val manifest: File,
        val blob: File,
        val ciphertext: ByteArray,
    )
}
