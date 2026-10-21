package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

@RunWith(RobolectricTestRunner::class)
class BoundaryTransferTest {
    @Test fun `recursive cross-root copy verifies bytes and preserves all sources`() =
        runBlocking {
            val source = sourceTree()
            val destination = MemoryEndpoint("destination", encrypted = true)
            BoundaryTransfer(
                RuntimeEnvironment.getApplication(),
            ).execute(source, source.entries.getValue("Photos"), destination, "", false)
            assertEquals(
                setOf("Photos", "Photos/Nested", "Photos/one.jpg", "Photos/Nested/two.jpg"),
                destination.entries.keys,
            )
            assertEquals("two", destination.contents.getValue("Photos/Nested/two.jpg").decodeToString())
            assertTrue(source.deleted.isEmpty())
        }

    @Test fun `recursive move deletes postorder only after the whole target is verified`() =
        runBlocking {
            val source = sourceTree()
            val destination = MemoryEndpoint("destination", encrypted = false)
            source.beforeDelete = { assertEquals(4, destination.entries.size) }
            BoundaryTransfer(
                RuntimeEnvironment.getApplication(),
            ).execute(source, source.entries.getValue("Photos"), destination, "", true)
            assertTrue(source.entries.isEmpty())
            assertEquals("Photos", source.deleted.last())
            assertTrue(source.deleted.indexOf("Photos/Nested/two.jpg") < source.deleted.indexOf("Photos/Nested"))
        }

    @Test fun `bad destination bytes never authorize source deletion`() {
        val source = sourceTree()
        val destination = MemoryEndpoint("destination", encrypted = false).apply { corruptRead = true }
        assertThrows(OpenCloudException::class.java) {
            runBlocking {
                BoundaryTransfer(
                    RuntimeEnvironment.getApplication(),
                ).execute(source, source.entries.getValue("Photos"), destination, "", true)
            }
        }
        assertTrue(source.deleted.isEmpty())
        assertEquals(4, source.entries.size)
    }

    @Test fun `source change after earlier copy retains the complete source tree`() {
        val source = sourceTree()
        val destination = MemoryEndpoint("destination", encrypted = true)
        destination.afterWrite = {
            source.entries["Photos/one.jpg"] = source.entries.getValue("Photos/one.jpg").copy(version = "changed")
        }
        assertThrows(OpenCloudException::class.java) {
            runBlocking {
                BoundaryTransfer(
                    RuntimeEnvironment.getApplication(),
                ).execute(source, source.entries.getValue("Photos"), destination, "", true)
            }
        }
        assertTrue(source.deleted.isEmpty())
    }

    @Test fun `cancelling a consumer closes a producer blocked on the bounded pipe`() =
        runBlocking {
            withTimeout(10_000) {
                repeat(8) {
                    val source = MemoryEndpoint("source", encrypted = true)
                    val entry = source.file("large", ByteArray(1024 * 1024))
                    val waiting = CompletableDeferred<Unit>()
                    val destination = MemoryEndpoint("destination", encrypted = false).apply { stall = waiting }
                    val task =
                        launch {
                            BoundaryTransfer(RuntimeEnvironment.getApplication()).execute(
                                source,
                                entry,
                                destination,
                                "",
                                true,
                            )
                        }
                    waiting.await()
                    task.cancelAndJoin()
                    assertTrue(source.deleted.isEmpty())
                    assertTrue(source.entries.containsKey("large"))
                    assertTrue(
                        RuntimeEnvironment.getApplication().noBackupFilesDir.listFiles().orEmpty().none {
                            it.name.startsWith("backup-traversal-")
                        },
                    )
                }
            }
        }

    @Test fun `consumer failure preserves its original error when the producer pipe is full`() {
        val body = ByteArray(1024 * 1024)
        val source = MemoryEndpoint("source", encrypted = true)
        val entry = source.file("large", body)
        val pipeFilled = CompletableDeferred<Unit>()
        val producer =
            object : BoundaryEndpoint by source {
                override suspend fun read(
                    entry: BoundaryEntry,
                    sink: OutputStream,
                ) {
                    source.requireUnchanged(entry)
                    sink.write(body, 0, 64 * 1024)
                    pipeFilled.complete(Unit)
                    sink.write(body, 64 * 1024, body.size - 64 * 1024)
                }
            }
        val destination = MemoryEndpoint("destination", encrypted = false)
        val expected = IOException("synthetic destination failure")
        val consumer =
            object : BoundaryEndpoint by destination {
                override suspend fun write(
                    parent: String,
                    name: String,
                    source: InputStream,
                    size: Long,
                    mimeType: String?,
                ): BoundaryEntry {
                    pipeFilled.await()
                    throw expected
                }
            }
        val observed =
            assertThrows(IOException::class.java) {
                runBlocking {
                    withTimeout(10_000) {
                        BoundaryTransfer(RuntimeEnvironment.getApplication()).execute(
                            producer,
                            entry,
                            consumer,
                            "",
                            true,
                        )
                    }
                }
            }
        assertEquals(expected.message, observed.message)
        // Coroutine stack-trace recovery may wrap the same error with its original as the cause.
        assertSame(expected, generateSequence<Throwable>(observed) { it.cause }.last())
        assertTrue(source.deleted.isEmpty())
        assertArrayEquals(body, source.contents.getValue("large"))
        assertTrue(destination.entries.isEmpty())
    }

    @Test fun `moving into own descendant is rejected before any write`() {
        val source = sourceTree()
        assertThrows(OpenCloudException::class.java) {
            runBlocking {
                BoundaryTransfer(
                    RuntimeEnvironment.getApplication(),
                ).execute(source, source.entries.getValue("Photos"), source, "Photos/Nested", true)
            }
        }
        assertEquals(4, source.entries.size)
        assertTrue(source.deleted.isEmpty())
    }

    private fun sourceTree(): MemoryEndpoint =
        MemoryEndpoint("source", encrypted = true).apply {
            directory("Photos")
            directory("Photos/Nested")
            file("Photos/one.jpg", "one".toByteArray())
            file("Photos/Nested/two.jpg", "two".toByteArray())
        }

    private class MemoryEndpoint(
        override val identity: String,
        override val encrypted: Boolean,
    ) : BoundaryEndpoint {
        val entries = linkedMapOf<String, BoundaryEntry>()
        val contents = mutableMapOf<String, ByteArray>()
        val deleted = mutableListOf<String>()
        var corruptRead = false
        var afterWrite: () -> Unit = {}
        var beforeDelete: () -> Unit = {}
        var stall: CompletableDeferred<Unit>? = null

        fun directory(path: String): BoundaryEntry =
            BoundaryEntry(path, path, path.substringAfterLast('/'), true, 0, "v1").also {
                entries[path] =
                    it
            }

        fun file(
            path: String,
            bytes: ByteArray,
        ): BoundaryEntry =
            BoundaryEntry(path, path, path.substringAfterLast('/'), false, bytes.size.toLong(), "v1").also {
                entries[path] = it
                contents[path] = bytes
            }

        override suspend fun list(path: String): List<BoundaryEntry> =
            entries.values.filter {
                it.path.substringBeforeLast('/', "") ==
                    path
            }

        override suspend fun requireUnchanged(entry: BoundaryEntry) {
            if (entries[entry.path] !=
                entry
            ) {
                throw OpenCloudException(eu.opencloud.android.next.core.network.OpenCloudError.PreconditionFailed)
            }
        }

        override suspend fun read(
            entry: BoundaryEntry,
            sink: OutputStream,
        ) {
            requireUnchanged(entry)
            sink.write(if (corruptRead) "bad".toByteArray() else contents.getValue(entry.path))
        }

        override suspend fun write(
            parent: String,
            name: String,
            source: InputStream,
            size: Long,
            mimeType: String?,
        ): BoundaryEntry {
            stall?.let {
                it.complete(Unit)
                awaitCancellation()
            }
            val path = listOf(parent, name).filter(String::isNotEmpty).joinToString("/")
            assertFalse(entries.containsKey(path))
            val result = file(path, source.readBytes())
            afterWrite()
            return result
        }

        override suspend fun createDirectory(
            parent: String,
            name: String,
        ): BoundaryEntry {
            val path = listOf(parent, name).filter(String::isNotEmpty).joinToString("/")
            assertFalse(entries.containsKey(path))
            return directory(path)
        }

        override suspend fun delete(entry: BoundaryEntry) {
            beforeDelete()
            if (entry.directory) assertTrue(list(entry.path).isEmpty()) else requireUnchanged(entry)
            entries.remove(entry.path)
            contents.remove(entry.path)
            deleted += entry.path
        }
    }
}
