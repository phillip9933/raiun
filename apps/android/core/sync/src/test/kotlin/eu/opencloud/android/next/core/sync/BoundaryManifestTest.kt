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

    @Test fun `snapshot child proof checks exact descriptors and complete frozen membership`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val children =
                (0 until 257).map { number ->
                    BoundaryEntry(
                        "child-$number",
                        "SecretFolder/file-$number",
                        "file-$number",
                        false,
                        3,
                        "\"v1\"",
                        "text/plain",
                    )
                }
            BoundaryManifest(context).use { manifest ->
                manifest.add(null, source, target)
                children.forEach { child ->
                    manifest.add(1, child, child.copy(id = "target-${child.id}", path = "Ordinary/${child.path}"))
                }
                captureBoundaryDirectory(context, source.path, guard = {}) { emit -> children.forEach(emit) }.use {
                    manifest.requireChildren(1, it)
                }
                val changed =
                    children.mapIndexed { index, child ->
                        if (index == 200) child.copy(mimeType = "changed") else child
                    }
                captureBoundaryDirectory(context, source.path, guard = {}) { emit ->
                    changed.forEach(emit)
                }.use { snapshot ->
                    val failure =
                        assertThrows(OpenCloudException::class.java) {
                            runBlocking { manifest.requireChildren(1, snapshot) }
                        }
                    assertEquals(OpenCloudError.PreconditionFailed, failure.error)
                }
                captureBoundaryDirectory(context, source.path, guard = {}) { emit ->
                    children.forEach(emit)
                    emit(children.first().copy(id = "extra", path = "SecretFolder/extra", name = "extra"))
                }.use { snapshot ->
                    val failure =
                        assertThrows(OpenCloudException::class.java) {
                            runBlocking { manifest.requireChildren(1, snapshot) }
                        }
                    assertEquals(OpenCloudError.PreconditionFailed, failure.error)
                }
            }
        }

    @Test fun `empty child proof refuses a revoked or closed operation snapshot`() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            BoundaryManifest(context).use { manifest ->
                manifest.add(null, source, target)
                var allowed = true
                captureBoundaryDirectory(context, source.path, guard = {
                    if (!allowed) throw OpenCloudException(OpenCloudError.AccessDenied)
                }) { }.use { empty ->
                    allowed = false
                    val failure =
                        assertThrows(OpenCloudException::class.java) {
                            runBlocking { manifest.requireChildren(1, empty) }
                        }
                    assertEquals(OpenCloudError.AccessDenied, failure.error)
                }
                val closed = captureBoundaryDirectory(context, source.path, guard = {}) { }
                closed.close()
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { manifest.requireChildren(1, closed) }
                    }
                assertEquals(OpenCloudError.PreconditionFailed, failure.error)
            }
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
