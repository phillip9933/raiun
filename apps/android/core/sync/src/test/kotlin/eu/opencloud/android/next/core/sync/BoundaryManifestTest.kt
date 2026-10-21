package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class BoundaryManifestTest {
    private val source = BoundaryEntry("sensitive-id", "SecretFolder", "SecretFolder", true, 0, "private-version")
    private val target = source.copy(id = "target-id", path = "Ordinary/SecretFolder")

    @Test fun `private spill never contains decrypted names versions or identity and removes files on close`() =
        runBlocking {
            val initial = spillFiles()
            BoundaryManifest(RuntimeEnvironment.getApplication()).use { manifest ->
                manifest.add(null, source, target)
                val file = (spillFiles() - initial).single { it.extension == "db" }
                val bytes = file.readBytes().toString(Charsets.ISO_8859_1)
                listOf(
                    "SecretFolder",
                    "Ordinary",
                    "private-version",
                    "sensitive-id",
                ).forEach { assertFalse(bytes.contains(it)) }
                val read = mutableListOf<BoundaryEntry>()
                manifest.forEach { read += it.source }
                assertEquals(listOf(source), read)
            }
            assertEquals(initial, spillFiles())
        }

    @Test fun `changed traversal parent fails authentication`() {
        val initial = spillFiles()
        BoundaryManifest(RuntimeEnvironment.getApplication()).use { manifest ->
            manifest.add(null, source, target)
            manifest.add(
                1,
                source.copy(id = "child", path = "SecretFolder/file", name = "file", directory = false),
                target.copy(id = "target-child", path = "Ordinary/SecretFolder/file", name = "file", directory = false),
            )
            val file = (spillFiles() - initial).single { it.extension == "db" }
            SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use {
                it.execSQL("UPDATE entry SET parent = 999 WHERE sequence = 2")
            }
            val error = assertThrows(OpenCloudException::class.java) { runBlocking { manifest.forEach { } } }
            assertEquals(OpenCloudError.InvalidResponse, error.error)
        }
        assertEquals(initial, spillFiles())
    }

    private fun spillFiles(): Set<File> =
        RuntimeEnvironment
            .getApplication()
            .noBackupFilesDir
            .listFiles()
            .orEmpty()
            .filter { it.name.startsWith("backup-traversal-") }
            .toSet()
}
