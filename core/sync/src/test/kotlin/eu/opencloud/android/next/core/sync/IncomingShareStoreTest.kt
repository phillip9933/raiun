package eu.opencloud.android.next.core.sync

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import androidx.room.Room
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.shadows.ShadowContentResolver
import java.io.File
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class IncomingShareStoreTest {
    private fun store(
        context: Context,
        availableBytes: (File) -> Long = { it.usableSpace },
    ) = IncomingShareStore(context, availableBytes) { _, _ -> true }

    @Test fun `misleading size does not weaken streamed limit and failed low-space intake removes partial files`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val source = File(context.cacheDir, "budget-original").apply { writeBytes(ByteArray(64 * 1024)) }
            val uri = Uri.parse("content://incoming.test/source")
            val mismatched = UUID.randomUUID().toString()
            register(SharedProvider(source, declaredSize = 1))
            val full = store(context).stage(mismatched, listOf(uri)) {}
            assertEquals(64L * 1024, full.single().payload.length())
            store(context).discard(mismatched)

            val lowSpace = UUID.randomUUID().toString()
            register(SharedProvider(source))
            val store = store(context) { 256L * 1024 * 1024 + 64 * 1024 }
            assertThrows(Exception::class.java) {
                runBlocking { store.stage(lowSpace, listOf(uri)) {} }
            }
            assertFalse(File(context.noBackupFilesDir, "incoming-shares/$lowSpace").exists())
        }

    @Test fun `submission retains a failed batch and retries the same identities and destination`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val original = File(context.cacheDir, "submit-original").apply { writeText("bytes") }
            register(SharedProvider(original))
            val id = UUID.randomUUID().toString()
            val store = store(context)
            val files = store.stage(id, listOf(Uri.parse("content://incoming.test/source"))) {}
            val destination = IncomingShareDestination("account", "space", "/target")
            var failed = false
            try {
                store.submit(id, destination) { throw java.io.IOException("queue unavailable") }
            } catch (_: java.io.IOException) {
                failed = true
            }
            assertTrue(failed)
            assertTrue(store.isStaged(id))
            assertEquals(destination, store.destination(id))
            val submitted = mutableListOf<String>()
            store.submit(id, destination) { submitted += it.id }
            assertEquals(files.map { it.id }, submitted)
            assertFalse(store.isStaged(id))
        }

    @Test fun `discard waits until submission finishes reading the intake source`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val original = File(context.cacheDir, "submit-concurrent").apply { writeText("bytes") }
            register(SharedProvider(original))
            val id = UUID.randomUUID().toString()
            val store = store(context)
            store.stage(id, listOf(Uri.parse("content://incoming.test/source"))) {}
            val started = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val submit =
                async {
                    store.submit(id, IncomingShareDestination("a", "s", "/")) {
                        started.complete(Unit)
                        release.await()
                        assertEquals("bytes", it.payload.readText())
                    }
                }
            withTimeout(5_000) { started.await() }
            val discard =
                async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                    store(context).discard(id)
                }
            assertFalse(discard.isCompleted)
            release.complete(Unit)
            withTimeout(5_000) {
                submit.await()
                discard.await()
            }
            assertFalse(store.isStaged(id))
        }

    @Test fun `unfinished intake staging is protected from the orphan sweep`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            try {
                val original = File(context.cacheDir, "staging-original").apply { writeText("bytes") }
                register(SharedProvider(original))
                val id = UUID.randomUUID().toString()
                val partial =
                    File(context.noBackupFilesDir, "incoming-shares/$id/0/partial").apply {
                        parentFile!!.mkdirs()
                        writeText("old partial")
                        setLastModified(1)
                    }
                var checks = 0
                store(context).stage(id, listOf(Uri.parse("content://incoming.test/source"))) {
                    if (++checks == 2) {
                        runBlocking<Unit> {
                            maintainPrivateCache(
                                context,
                                FileBrowserStore(database),
                                System.currentTimeMillis(),
                            )
                        }
                        assertTrue(partial.exists())
                    }
                }
                assertTrue(checks >= 2)
            } finally {
                database.close()
            }
        }

    @Test fun `discard in another instance waits for staging before removing the batch`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val original = File(context.cacheDir, "concurrent-original").apply { writeText("bytes") }
            register(SharedProvider(original))
            val id = UUID.randomUUID().toString()
            val started = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            var checks = 0
            val staging =
                async(Dispatchers.IO) {
                    store(context).stage(id, listOf(Uri.parse("content://incoming.test/source"))) {
                        if (++checks == 2) {
                            started.complete(Unit)
                            runBlocking<Unit> { withTimeout(5_000) { release.await() } }
                        }
                    }
                }
            withTimeout(5_000) { started.await() }
            val discard =
                async(start = kotlinx.coroutines.CoroutineStart.UNDISPATCHED) {
                    store(context).discard(id)
                }
            assertFalse(discard.isCompleted)
            release.complete(Unit)
            withTimeout(5_000) {
                staging.await()
                discard.await()
            }
            assertFalse(File(context.noBackupFilesDir, "incoming-shares/$id").exists())
            store(context).discard(id)
        }

    @Test fun `unknown mime filenames survive staging and restart after provider access disappears`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val original = File(context.cacheDir, "original").apply { writeText("exact original bytes") }
            register(SharedProvider(original))
            val id = UUID.randomUUID().toString()
            val store = store(context)
            val files =
                store.stage(
                    id,
                    listOf(
                        Uri.parse("content://incoming.test/database.dbf"),
                        Uri.parse("content://incoming.test/backup.jwlibrary"),
                    ),
                ) {}
            assertEquals(listOf("database.dbf", "backup.jwlibrary"), files.map { it.name })
            original.delete()
            val restored = store(context).stage(id, emptyList()) {}
            assertEquals(files.map { it.id }, restored.map { it.id })
            restored.forEach { assertEquals("exact original bytes", it.payload.readText()) }
            store.discard(id)
        }

    @Test fun `unsafe source schemes filenames and cancelled reads never publish a batch`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val store = store(context)
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking<Unit> {
                    store.stage(
                        UUID.randomUUID().toString(),
                        listOf(Uri.parse("file:///private/secret")),
                    ) {}
                }
            }
            val original = File(context.cacheDir, "original").apply { writeText("bytes") }
            register(SharedProvider(original, "../escape"))
            assertThrows(IllegalArgumentException::class.java) {
                runBlocking<Unit> {
                    store.stage(
                        UUID.randomUUID().toString(),
                        listOf(Uri.parse("content://incoming.test/source")),
                    ) {}
                }
            }
            val cancelledBatch = UUID.randomUUID().toString()
            assertThrows(java.util.concurrent.CancellationException::class.java) {
                runBlocking<Unit> {
                    store.stage(cancelledBatch, listOf(Uri.parse("content://incoming.test/source"))) {
                        throw java.util.concurrent.CancellationException()
                    }
                }
            }
            assertFalse(File(context.noBackupFilesDir, "incoming-shares/$cancelledBatch").exists())
            register(
                SharedProvider(File(context.cacheDir, "cancel-original").apply { writeBytes(ByteArray(256 * 1024)) }),
            )
            val interruptedBatch = UUID.randomUUID().toString()
            var checks = 0
            assertThrows(java.util.concurrent.CancellationException::class.java) {
                runBlocking<Unit> {
                    store.stage(interruptedBatch, listOf(Uri.parse("content://incoming.test/source"))) {
                        if (++checks >= 6) throw java.util.concurrent.CancellationException()
                    }
                }
            }
            assertFalse(File(context.noBackupFilesDir, "incoming-shares/$interruptedBatch").exists())
        }

    private fun register(provider: SharedProvider) {
        provider.attachInfo(
            RuntimeEnvironment.getApplication(),
            android.content.pm.ProviderInfo().apply {
                authority = "incoming.test"
            },
        )
        ShadowContentResolver.registerProviderInternal("incoming.test", provider)
    }

    @Test fun `partially queued batch retains destination after restart and cannot switch accounts`() =
        runBlocking<Unit> {
            val context = RuntimeEnvironment.getApplication()
            val original = File(context.cacheDir, "original").apply { writeText("bytes") }
            register(SharedProvider(original))
            val batch = UUID.randomUUID().toString()
            val store = store(context)
            store.stage(batch, listOf(Uri.parse("content://incoming.test/photo.jpg"))) {}
            val destination = IncomingShareDestination("account", "space", "/Photos/Camera")
            store.rememberDestination(batch, destination)
            val manifest = File(context.noBackupFilesDir, "incoming-shares/$batch/manifest.json")
            org.junit.Assert.assertTrue(manifest.renameTo(File(manifest.path + ".bak")))
            val restored = store(context)
            assertEquals(1, restored.stage(batch, emptyList()) {}.size)
            assertEquals(destination, restored.destination(batch))
            restored.rememberDestination(batch, destination)
            assertThrows(IllegalStateException::class.java) {
                restored.rememberDestination(batch, destination.copy(accountId = "other account"))
            }
        }

    private class SharedProvider(
        private val source: File,
        private val name: String? = null,
        private val declaredSize: Long? = null,
    ) : ContentProvider() {
        override fun onCreate() = true

        override fun getType(uri: Uri): String? = null

        override fun openFile(
            uri: Uri,
            mode: String,
        ): ParcelFileDescriptor = ParcelFileDescriptor.open(source, ParcelFileDescriptor.MODE_READ_ONLY)

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            selectionArgs: Array<out String>?,
            sortOrder: String?,
        ) = MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)).apply {
            addRow(arrayOf(name ?: uri.lastPathSegment, declaredSize))
        }

        override fun insert(
            uri: Uri,
            values: ContentValues?,
        ): Uri? = null

        override fun delete(
            uri: Uri,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0
    }
}
