package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import org.junit.After
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
import java.io.File

@RunWith(RobolectricTestRunner::class)
class VaultOfflineIndexTest {
    @get:Rule val temporary = TemporaryFolder()

    private val material = ByteArray(80) { it.toByte() }
    private val identity = VaultIdentity("account", "https://example.test/", "drive", "vault-id")
    private val location =
        VaultLocation(
            accountId = "account",
            title = "Secret.vault",
            kind = VaultLocationKind.FOLDER_VAULT,
            driveId = "drive",
            remoteVaultId = "vault-id",
            sourceRootId = "root-id",
            canonicalServer = "https://example.test/",
            rootWebDavUrl = "https://example.test/dav/files/",
            vaultPath = "Secret.vault",
            isVaultRoot = true,
        )

    @After fun wipeMaterial() {
        material.fill(0)
    }

    @Test fun aggregateIndexBeyondOldManifestLimitIsWrittenAndQueriedFromStreamingSource() {
        val directory = temporary.newFolder()
        val padding = "x".repeat(8192)
        var sourceVisits = 0
        val source =
            object : OfflineManifest {
                override fun visit(
                    checkActive: () -> Unit,
                    consume: (OfflineEntry) -> Unit,
                ) {
                    sourceVisits++
                    repeat(2049) { number ->
                        checkActive()
                        consume(folder(number).copy(id = "$number:$padding"))
                    }
                }
            }
        val root =
            VaultOfflineIndex.prepare(
                directory,
                identity,
                location,
                material,
                source,
                durability = jvmOfflineDurability(directory),
            )
        assertEquals(1, sourceVisits)
        assertTrue(root.size < 512)
        assertTrue(indexFile(directory, root).length() > 16L * 1024 * 1024)
        VaultOfflineIndex.open(directory, identity, location, material, root).use { index ->
            var count = 0L
            index.visit { entry ->
                assertEquals("Secret.vault/opaque-$count", entry.encryptedPath)
                count++
            }
            assertEquals(2049L, count)
            assertEquals("0:$padding", index.find("Secret.vault/opaque-0")?.id)
            assertEquals("2048:$padding", index.find("Secret.vault/opaque-2048")?.id)
            assertEquals(null, index.find("Secret.vault/missing"))
        }
    }

    @Test fun oneLegacySizedRecordIsChunkedPastCursorWindowAndRetainsEveryField() {
        val directory = temporary.newFolder()
        val entry = folder(0).copy(id = "opaque-" + "y".repeat(3 * 1024 * 1024))
        val root = prepare(directory, listOf(entry))
        SQLiteDatabase
            .openDatabase(indexFile(directory, root).path, null, SQLiteDatabase.OPEN_READONLY)
            .use { database ->
                database.rawQuery("SELECT COUNT(*), MAX(length(payload)) FROM chunks", null).use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    assertTrue(cursor.getLong(0) > 1)
                    assertTrue(cursor.getLong(1) <= 64 * 1024)
                }
            }
        VaultOfflineIndex.open(directory, identity, location, material, root).use { index ->
            assertEquals(entry, index.find(entry.encryptedPath))
        }
    }

    @Test fun missingRequestedOrTailRecordCannotTurnFullMembershipFailureIntoAValidFindResult() {
        listOf(1, 2).forEach { removed ->
            val directory = temporary.newFolder()
            val root = prepare(directory, List(3, ::folder))
            VaultOfflineIndex.open(directory, identity, location, material, root).use { index ->
                mutate(directory, root) {
                    it.execSQL("DELETE FROM chunks WHERE seq = $removed")
                    it.execSQL("DELETE FROM entries WHERE seq = $removed")
                }
                assertThrows(OpenCloudException::class.java) { index.find("Secret.vault/opaque-$removed") }
                assertThrows(OpenCloudException::class.java) { index.find("Secret.vault/opaque-0") }
                assertThrows(OpenCloudException::class.java) { index.find("Secret.vault/absent") }
            }
        }
    }

    @Test fun modifiedTokenSequencePayloadChunkOrderAndOrphanChunksAreRejectedByWholeScan() {
        val mutations =
            listOf<(SQLiteDatabase) -> Unit>(
                { it.execSQL("UPDATE entries SET pathToken = zeroblob(32) WHERE seq = 1") },
                { it.execSQL("UPDATE entries SET seq = 8 WHERE seq = 1") },
                { it.execSQL("UPDATE chunks SET payload = zeroblob(length(payload)) WHERE seq = 1 AND part = 0") },
                { it.execSQL("UPDATE chunks SET part = 1 WHERE seq = 1 AND part = 0") },
                { it.execSQL("INSERT INTO chunks(seq, part, payload) VALUES(999, 0, X'00')") },
            )
        mutations.forEach { mutation ->
            val directory = temporary.newFolder()
            val root = prepare(directory, List(3, ::folder))
            VaultOfflineIndex.open(directory, identity, location, material, root).use { index ->
                mutate(directory, root, mutation)
                assertThrows(OpenCloudException::class.java) { index.find("Secret.vault/opaque-0") }
            }
        }
    }

    @Test fun oversizedUntrustedSqlBlobsFailAsIntegrityErrorsBeforeCursorWindowMaterialization() {
        val mutations =
            listOf(
                "UPDATE entries SET pathToken = zeroblob(8 * 1024 * 1024) WHERE seq = 1",
                "UPDATE chunks SET payload = zeroblob(8 * 1024 * 1024) WHERE seq = 1 AND part = 0",
            )
        mutations.forEach { sql ->
            val directory = temporary.newFolder()
            val root = prepare(directory, List(3, ::folder))
            VaultOfflineIndex.open(directory, identity, location, material, root).use { index ->
                mutate(directory, root) { it.execSQL(sql) }
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        index.find("Secret.vault/opaque-0")
                    }
                assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
            }
        }
    }

    @Test fun rootAuthenticationBindsKeyIdentityExactLocationAndGeneration() {
        val directory = temporary.newFolder()
        val root = prepare(directory, List(2, ::folder))
        val damaged = root.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertThrows(OpenCloudException::class.java) {
            VaultOfflineIndex.open(directory, identity, location, material, damaged).use { it.visit {} }
        }
        val wrongKey = material.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        try {
            assertThrows(OpenCloudException::class.java) {
                VaultOfflineIndex.open(directory, identity, location, wrongKey, root).use { it.visit {} }
            }
        } finally {
            wrongKey.fill(0)
        }
        assertThrows(OpenCloudException::class.java) {
            VaultOfflineIndex
                .open(
                    directory,
                    identity.copy(accountId = "other"),
                    location,
                    material,
                    root,
                ).use { it.visit {} }
        }
        assertThrows(OpenCloudException::class.java) {
            VaultOfflineIndex
                .open(
                    directory,
                    identity,
                    location.copy(sourceRootId = "replacement-root"),
                    material,
                    root,
                ).use { it.visit {} }
        }
        val donor = prepare(directory, List(2, ::folder))
        val substituted = root.copyOf().also { donor.copyInto(it, 4, 4, 40) }
        assertThrows(OpenCloudException::class.java) {
            VaultOfflineIndex.open(directory, identity, location, material, substituted).use { it.visit {} }
        }
    }

    @Test fun legacySizedUtf8LocationDoesNotAcquireAModifiedUtf8LengthCeiling() {
        val directory = temporary.newFolder()
        val captured = location.copy(title = "\uD83D\uDE42".repeat(12_000))
        assertTrue(encodeLocation(captured).toByteArray(Charsets.UTF_8).size < 64 * 1024)
        val root =
            VaultOfflineIndex.prepare(
                directory,
                identity,
                captured,
                material,
                LegacyOfflineManifest(mapOf(folder(0).encryptedPath to folder(0))),
                durability = jvmOfflineDurability(directory),
            )
        VaultOfflineIndex.open(directory, identity, captured, material, root).use { index ->
            assertEquals(folder(0), index.find(folder(0).encryptedPath))
        }
    }

    @Test fun swappingAWholeValidDatabaseCannotAuthenticateUnderAnotherGenerationRoot() {
        val directory = temporary.newFolder()
        val first = prepare(directory, List(2, ::folder))
        val second = prepare(directory, listOf(folder(0).copy(id = "different"), folder(1)))
        VaultOfflineIndex.open(directory, identity, location, material, first).use { index ->
            indexFile(directory, first).writeBytes(indexFile(directory, second).readBytes())
            assertThrows(OpenCloudException::class.java) { index.find("Secret.vault/opaque-0") }
        }
    }

    @Test fun cleanupRetainsOpenGenerationUntilLastReaderClosesAndPreservesUnrelatedFiles() {
        val directory = temporary.newFolder()
        val first = prepare(directory, List(2, ::folder))
        val second = prepare(directory, listOf(folder(2)))
        val sentinel = File(directory, "indexes/recovery-note.txt").apply { writeText("preserve") }
        val reader = VaultOfflineIndex.open(directory, identity, location, material, first)
        val otherReader = VaultOfflineIndex.open(directory, identity, location, material, first)
        try {
            VaultOfflineIndex.cleanup(directory, listOf(second))
            assertTrue(indexFile(directory, first).isFile)
            assertEquals(folder(1), reader.find(folder(1).encryptedPath))
            reader.close()
            VaultOfflineIndex.cleanup(directory, listOf(second))
            assertTrue(indexFile(directory, first).isFile)
            assertEquals(folder(0), otherReader.find(folder(0).encryptedPath))
        } finally {
            reader.close()
            otherReader.close()
        }
        VaultOfflineIndex.cleanup(directory, listOf(second))
        assertFalse(indexFile(directory, first).exists())
        assertTrue(indexFile(directory, second).isFile)
        assertEquals("preserve", sentinel.readText())
    }

    @Test fun cleanupRecognizesReaderLeasesAcrossEquivalentPrivateDirectoryPaths() {
        val directory = temporary.newFolder()
        val first = prepare(directory, listOf(folder(0)))
        val second = prepare(directory, listOf(folder(1)))
        val alias = File(directory, "../${directory.name}")
        VaultOfflineIndex.open(alias, identity, location, material, first).use { reader ->
            VaultOfflineIndex.cleanup(directory, listOf(second))
            assertTrue(indexFile(directory, first).isFile)
            assertEquals(folder(0), reader.find(folder(0).encryptedPath))
        }
        VaultOfflineIndex.cleanup(directory, listOf(second))
        assertFalse(indexFile(directory, first).exists())
    }

    @Test fun cancelledPreparationRemovesOnlyItsUnpublishedGenerationAndLeavesOldRootUsable() {
        val directory = temporary.newFolder()
        val original = prepare(directory, List(2, ::folder))
        val bytes = indexFile(directory, original).readBytes()
        val before =
            File(directory, "indexes")
                .listFiles()
                .orEmpty()
                .map(File::getName)
                .toSet()
        val source =
            object : OfflineManifest {
                override fun visit(
                    checkActive: () -> Unit,
                    consume: (OfflineEntry) -> Unit,
                ) {
                    repeat(129) {
                        checkActive()
                        consume(folder(it))
                    }
                    throw CancellationException("synthetic stop after committed staging batch")
                }
            }
        assertThrows(CancellationException::class.java) {
            VaultOfflineIndex.prepare(
                directory,
                identity,
                location,
                material,
                source,
                durability = jvmOfflineDurability(directory),
            )
        }
        assertEquals(
            before,
            File(directory, "indexes")
                .listFiles()
                .orEmpty()
                .map(File::getName)
                .toSet(),
        )
        assertArrayEquals(bytes, indexFile(directory, original).readBytes())
        VaultOfflineIndex.open(directory, identity, location, material, original).use { index ->
            assertEquals(folder(1), index.find(folder(1).encryptedPath))
        }
    }

    private fun folder(number: Int): OfflineEntry =
        OfflineEntry("Secret.vault/opaque-$number", "opaque-$number", "id-$number", true, 0, null, null, null)

    private fun prepare(
        directory: File,
        entries: List<OfflineEntry>,
    ): ByteArray =
        VaultOfflineIndex.prepare(
            directory,
            identity,
            location,
            material,
            LegacyOfflineManifest(entries.associateBy(OfflineEntry::encryptedPath)),
            durability = jvmOfflineDurability(directory),
        )

    private fun indexFile(
        directory: File,
        root: ByteArray,
    ): File = File(directory, "indexes/${requireNotNull(VaultOfflineIndex.generation(root))}.db")

    private fun mutate(
        directory: File,
        root: ByteArray,
        action: (SQLiteDatabase) -> Unit,
    ) {
        SQLiteDatabase.openDatabase(indexFile(directory, root).path, null, SQLiteDatabase.OPEN_READWRITE).use(action)
    }
}
