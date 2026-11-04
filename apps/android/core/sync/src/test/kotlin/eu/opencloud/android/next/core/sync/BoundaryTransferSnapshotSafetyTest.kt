package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.InputStream
import java.io.OutputStream

/** Independent traversal oracle: legacy list is forbidden and snapshots use the real encrypted store. */
@RunWith(RobolectricTestRunner::class)
class BoundaryTransferSnapshotSafetyTest {
    private val context = RuntimeEnvironment.getApplication()

    @Test fun completeCrossBatchRecursiveCopyIncludesHiddenChildrenWithoutLegacyLists() =
        runBlocking<Unit> {
            val source = Endpoint("source")
            val root = source.directory("root")
            repeat(300) { source.file("root/${it.toString().padStart(4, '0')}.txt") }
            source.file("root/.hidden.txt")
            source.directory("root/nested")
            source.file("root/nested/.nested-hidden.txt")
            val target = Endpoint("target")
            BoundaryTransfer(context).execute(source, root, target, "", false)
            assertEquals(source.entries.keys, target.entries.keys)
            source.bytes.forEach { (path, bytes) -> assertArrayEquals(bytes, target.bytes[path]) }
            assertTrue(source.deleted.isEmpty())
            assertTrue(target.entries.containsKey("root/.hidden.txt"))
            assertTrue(target.entries.containsKey("root/nested/.nested-hidden.txt"))
            assertEquals(302, target.fileWrites)
        }

    @Test fun trailingInvalidMetadataOrOrdinaryVaultMarkerPreventsEveryChildCopyCallback() {
        for (error in listOf(OpenCloudError.InvalidResponse, OpenCloudError.AccessDenied)) {
            val source = Endpoint("source")
            val root = source.directory("root")
            repeat(257) { source.file("root/file-$it") }
            // Simulate a fully read endpoint response whose trailing metadata/ordinary marker is refused.
            // Actual DAV parsing/marker classification belongs to the endpoint protocol tests.
            source.captureFailure = error
            val target = Endpoint("target")
            val failure =
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { BoundaryTransfer(context).execute(source, root, target, "", true) }
                }
            assertEquals(error, failure.error)
            assertEquals(0, target.fileWrites)
            assertEquals(setOf("root"), target.entries.keys) // Prior root-directory creation is existing behavior.
            assertTrue(source.deleted.isEmpty())
        }
    }

    @Test fun sameCountSourceIdentityVersionOrMimeChangesFailCompleteProofBeforeFirstDelete() {
        val substitutions: List<(BoundaryEntry) -> BoundaryEntry> =
            listOf(
                { it.copy(id = "replaced-id") },
                { it.copy(version = "\"changed-version\"") },
                { it.copy(mimeType = "application/changed") },
            )
        for (substitute in substitutions) {
            val source = Endpoint("source")
            val root = source.directory("root")
            repeat(257) { source.file("root/file-$it") }
            val target = Endpoint("target")
            source.beforeCapture = { path, count ->
                if (path == "root" && count == 2) {
                    source.entries["root/file-256"] = substitute(source.entries.getValue("root/file-256"))
                }
            }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { BoundaryTransfer(context).execute(source, root, target, "", true) }
            }
            assertEquals(257, target.fileWrites)
            assertEquals(258, source.entries.size)
            assertTrue(source.deleted.isEmpty())
        }
    }

    private class Endpoint(
        override val identity: String,
    ) : BoundaryEndpoint {
        override val encrypted = false
        val entries = linkedMapOf<String, BoundaryEntry>()
        val bytes = linkedMapOf<String, ByteArray>()
        val deleted = mutableListOf<String>()
        var fileWrites = 0
        var captureFailure: OpenCloudError? = null
        var beforeCapture: (String, Int) -> Unit = { _, _ -> }
        private val captures = mutableMapOf<String, Int>()
        private var nextId = 0

        fun directory(path: String): BoundaryEntry = entry(path, true, 0).also { entries[path] = it }

        fun file(path: String): BoundaryEntry {
            val content = path.toByteArray()
            bytes[path] = content
            return entry(path, false, content.size.toLong()).also { entries[path] = it }
        }

        override suspend fun list(path: String): List<BoundaryEntry> = error("Recursive traversal must use a snapshot")

        override suspend fun openDirectory(
            context: Context,
            path: String,
        ): BoundaryDirectorySnapshot {
            val count = captures.getOrDefault(path, 0) + 1
            captures[path] = count
            beforeCapture(path, count)
            return captureBoundaryDirectory(context, path, {}) { emit ->
                entries.values.filter { it.path.substringBeforeLast('/', "") == path }.forEach(emit)
                captureFailure?.let { throw OpenCloudException(it) }
            }
        }

        override suspend fun requireUnchanged(entry: BoundaryEntry) {
            val current = entries[entry.path] ?: throw OpenCloudException(OpenCloudError.NotFound)
            if (!sameBoundaryEntry(entry, current)) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }

        override suspend fun read(
            entry: BoundaryEntry,
            sink: OutputStream,
        ) {
            requireUnchanged(entry)
            sink.write(bytes.getValue(entry.path))
        }

        override suspend fun write(
            parent: String,
            name: String,
            source: InputStream,
            size: Long,
            mimeType: String?,
        ): BoundaryEntry {
            val path = childPath(parent, name)
            if (entries.containsKey(path)) throw OpenCloudException(OpenCloudError.Conflict)
            val content = source.readBytes()
            assertEquals(size, content.size.toLong())
            bytes[path] = content
            fileWrites++
            return entry(path, false, size).copy(mimeType = mimeType).also { entries[path] = it }
        }

        override suspend fun createDirectory(
            parent: String,
            name: String,
        ): BoundaryEntry = directory(childPath(parent, name))

        override suspend fun delete(entry: BoundaryEntry) {
            requireUnchanged(entry)
            if (entry.directory && entries.values.any { it.path.substringBeforeLast('/', "") == entry.path }) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            deleted += entry.path
            entries.remove(entry.path)
            bytes.remove(entry.path)
        }

        private fun entry(
            path: String,
            directory: Boolean,
            size: Long,
        ) = BoundaryEntry(
            "$identity-${++nextId}",
            path,
            path.substringAfterLast('/'),
            directory,
            size,
            "\"v1\"",
            null,
        )
    }
}
