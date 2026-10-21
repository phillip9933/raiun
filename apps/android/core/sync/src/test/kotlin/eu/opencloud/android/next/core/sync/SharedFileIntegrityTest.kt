package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.SharedLocalFile
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class SharedFileIntegrityTest {
    private val directory = Files.createTempDirectory("shared-bytes-").toFile()

    @After fun close() {
        directory.deleteRecursively()
    }

    @Test fun fingerprintAndCorruption() =
        runBlocking {
            val file = File(directory, "file").apply { writeText("hello") }
            val commit = SharedFileIntegrity.inspect(directory, file.path, 5, 1)
            assertEquals("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", commit.sha256)
            val cached =
                SharedLocalFile("a", "scope", "file", "/file", 5, "etag", commit.localPath, commit.sha256, 1, false)
            assertTrue(SharedFileIntegrity.matches(directory, cached))
            file.writeText("other")
            assertFalse(SharedFileIntegrity.matches(directory, cached))
            file.writeText("shorter file")
            assertFalse(SharedFileIntegrity.matches(directory, cached))
            file.delete()
            assertFalse(SharedFileIntegrity.matches(directory, cached))
        }

    @Test fun containmentAndLength() {
        val child = File(directory, "nested").apply { mkdirs() }
        val file = File(child, "file").apply { writeText("hello") }
        assertThrows(OpenCloudException::class.java) {
            runBlocking { SharedFileIntegrity.inspect(directory, file.path, 5, 1) }
        }
        assertThrows(OpenCloudException::class.java) {
            runBlocking { SharedFileIntegrity.inspect(child, file.path, 6, 1) }
        }
    }

    @Test fun cancellationPropagates() {
        val file = File(directory, "file").apply { writeText("hello") }
        assertThrows(CancellationException::class.java) {
            runBlocking {
                withContext(Job().also { it.cancel() }) {
                    SharedFileIntegrity.inspect(directory, file.path, 5, 1)
                }
            }
        }
    }
}
