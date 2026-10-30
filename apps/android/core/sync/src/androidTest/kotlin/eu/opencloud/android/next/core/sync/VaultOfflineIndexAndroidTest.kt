package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Actual Android SQLite/CursorWindow/JCA; synthetic metadata, no account or network operations. */
@RunWith(AndroidJUnit4::class)
class VaultOfflineIndexAndroidTest {
    private val identity = VaultIdentity("native-account", "https://example.test/", "drive", "vault-id")
    private val location =
        VaultLocation(
            accountId = identity.accountId,
            title = "Secret.vault",
            kind = VaultLocationKind.FOLDER_VAULT,
            driveId = identity.driveId,
            remoteVaultId = identity.remoteVaultId,
            sourceRootId = "root-id",
            canonicalServer = identity.canonicalServer,
            rootWebDavUrl = "https://example.test/dav/files/",
            vaultPath = "Secret.vault",
            isVaultRoot = true,
        )

    @Test fun nativeSqliteStreamsAnAggregateBeyondSixteenMiBWithSmallAuthenticatedRoot() =
        fixture { directory, material ->
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
                            consume(folder(number).copy(id = "$PRIVATE_MARKER$number:$padding"))
                        }
                    }
                }
            val root = VaultOfflineIndex.prepare(directory, identity, location, material, source)
            assertEquals(1, sourceVisits)
            assertTrue(root.size < 512)
            val file = indexFile(directory, root)
            assertTrue(file.length() > 16L * 1024 * 1024)
            SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READONLY).use { database ->
                database.rawQuery("PRAGMA journal_mode", null).use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    assertEquals("delete", cursor.getString(0).lowercase())
                }
            }
            VaultOfflineIndex.open(directory, identity, location, material, root).use { index ->
                var count = 0L
                index.visit { entry ->
                    assertEquals(folder(count.toInt()).copy(id = "$PRIVATE_MARKER$count:$padding"), entry)
                    count++
                }
                assertEquals(2049L, count)
                assertEquals(
                    folder(2048).copy(id = "${PRIVATE_MARKER}2048:$padding"),
                    index.find(folder(2048).encryptedPath),
                )
            }
            assertNoReadableMarker(file)
        }

    @Test fun nativeCursorWindowReadsThreeMiBRecordThroughBoundedChunksAndRejectsTailTampering() =
        fixture { directory, material ->
            val expected = folder(0).copy(id = PRIVATE_MARKER + "y".repeat(3 * 1024 * 1024))
            val root = prepare(directory, material, listOf(expected))
            val file = indexFile(directory, root)
            SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READONLY).use { database ->
                database.rawQuery("SELECT COUNT(*), MAX(length(payload)) FROM chunks", null).use { cursor ->
                    assertTrue(cursor.moveToFirst())
                    assertTrue(cursor.getLong(0) > 32)
                    assertTrue(cursor.getLong(1) <= 64 * 1024)
                }
            }
            VaultOfflineIndex.open(directory, identity, location, material, root).use { index ->
                assertEquals(expected, index.find(expected.encryptedPath))
                SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use { database ->
                    database.execSQL(
                        "UPDATE chunks SET payload = zeroblob(length(payload)) " +
                            "WHERE seq = 0 AND part = (SELECT MAX(part) FROM chunks WHERE seq = 0)",
                    )
                }
                val failure = assertThrows(OpenCloudException::class.java) { index.find(expected.encryptedPath) }
                assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
            }
            val damaged = root.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            assertThrows(OpenCloudException::class.java) {
                VaultOfflineIndex.open(directory, identity, location, material, damaged).use { it.visit {} }
            }
        }

    @Test fun nativeMembershipGuardsAndReaderCleanupPreserveOnlyOwnedAcceptedGenerations() =
        fixture { directory, material ->
            val first = prepare(directory, material, List(3, ::folder))
            val next = prepare(directory, material, listOf(folder(3)))
            val firstFile = indexFile(directory, first)
            val sentinel = File(directory, "indexes/unrelated-evidence.txt").apply { writeText("preserve") }
            VaultOfflineIndex.open(directory, identity, location, material, first).use { index ->
                val denied =
                    assertThrows(OpenCloudException::class.java) {
                        index.find(folder(0).encryptedPath) { throw OpenCloudException(OpenCloudError.AccessDenied) }
                    }
                assertEquals(OpenCloudError.AccessDenied, denied.error)
                assertEquals(folder(0), index.find(folder(0).encryptedPath))
                VaultOfflineIndex.cleanup(directory, listOf(next))
                assertTrue(firstFile.isFile)
                SQLiteDatabase.openDatabase(firstFile.path, null, SQLiteDatabase.OPEN_READWRITE).use { database ->
                    database.execSQL("DELETE FROM chunks WHERE seq = 2")
                    database.execSQL("DELETE FROM entries WHERE seq = 2")
                }
                for (path in listOf(folder(0).encryptedPath, folder(2).encryptedPath, "Secret.vault/missing")) {
                    val failure = assertThrows(OpenCloudException::class.java) { index.find(path) }
                    assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
                }
                assertTrue(firstFile.isFile)
            }
            VaultOfflineIndex.cleanup(directory, listOf(next))
            assertFalse(firstFile.exists())
            assertTrue(indexFile(directory, next).isFile)
            assertEquals("preserve", sentinel.readText())

            val before =
                File(directory, "indexes")
                    .listFiles()
                    .orEmpty()
                    .map(File::getName)
                    .toSet()
            val interrupted =
                object : OfflineManifest {
                    override fun visit(
                        checkActive: () -> Unit,
                        consume: (OfflineEntry) -> Unit,
                    ) {
                        repeat(129) {
                            checkActive()
                            consume(folder(it))
                        }
                        throw CancellationException("synthetic cancellation after persisted staging batch")
                    }
                }
            assertThrows(CancellationException::class.java) {
                VaultOfflineIndex.prepare(directory, identity, location, material, interrupted)
            }
            assertEquals(
                before,
                File(directory, "indexes")
                    .listFiles()
                    .orEmpty()
                    .map(File::getName)
                    .toSet(),
            )
            VaultOfflineIndex.open(directory, identity, location, material, next).use { index ->
                assertEquals(folder(3), index.find(folder(3).encryptedPath))
            }
        }

    private fun fixture(block: (File, ByteArray) -> Unit) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.noBackupFilesDir, "offline-index-native-${UUID.randomUUID()}")
        val material = ByteArray(80) { it.toByte() }
        assertTrue(directory.mkdirs())
        try {
            block(directory, material)
        } finally {
            material.fill(0)
            directory.deleteRecursively()
        }
    }

    private fun folder(number: Int): OfflineEntry =
        OfflineEntry("Secret.vault/opaque-$number", "opaque-$number", "id-$number", true, 0, null, null, null)

    private fun prepare(
        directory: File,
        material: ByteArray,
        entries: List<OfflineEntry>,
    ): ByteArray =
        VaultOfflineIndex.prepare(
            directory,
            identity,
            location,
            material,
            LegacyOfflineManifest(entries.associateBy(OfflineEntry::encryptedPath)),
        )

    private fun indexFile(
        directory: File,
        root: ByteArray,
    ): File = File(directory, "indexes/${requireNotNull(VaultOfflineIndex.generation(root))}.db")

    private fun assertNoReadableMarker(file: File) {
        val marker = PRIVATE_MARKER.toByteArray(Charsets.US_ASCII)
        val buffer = ByteArray(64 * 1024 + marker.size)
        try {
            file.inputStream().use { input ->
                var carry = 0
                while (true) {
                    val count = input.read(buffer, carry, 64 * 1024)
                    if (count < 0) break
                    val size = carry + count
                    assertFalse(String(buffer, 0, size, Charsets.ISO_8859_1).contains(PRIVATE_MARKER))
                    carry = minOf(marker.size - 1, size)
                    buffer.copyInto(buffer, 0, size - carry, size)
                }
            }
        } finally {
            marker.fill(0)
            buffer.fill(0)
        }
    }

    private companion object {
        const val PRIVATE_MARKER = "native-private-metadata-"
    }
}
