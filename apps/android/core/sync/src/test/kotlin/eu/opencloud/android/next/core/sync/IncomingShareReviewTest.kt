package eu.opencloud.android.next.core.sync

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.PackageInfo
import android.content.pm.ProviderInfo
import android.database.MatrixCursor
import android.net.Uri
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.shadows.ShadowContentResolver
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class IncomingShareReviewTest {
    private val context = RuntimeEnvironment.getApplication()
    private val uri = Uri.parse("content://review.test/source")

    @Test fun `review shows bounded metadata and provider package without opening or staging content`() =
        runBlocking {
            val provider = register(MetadataProvider("photo.jpg"))
            val result = IncomingShareStore(context).review(listOf(uri)).single()
            assertEquals("photo.jpg", result.name)
            assertEquals("example.provider", result.providerPackage)
            assertEquals(1, provider.queries)
            assertEquals(0, provider.opens)
            assertEquals(listOf(OpenableColumns.DISPLAY_NAME), provider.projection)
            assertFalse(File(context.noBackupFilesDir, "incoming-shares").exists())
        }

    @Test fun `unknown and failing providers leave unknown metadata without guessing from URI`() =
        runBlocking {
            val unknown =
                IncomingShareStore(
                    context,
                ).review(listOf(Uri.parse("content://missing.test/private-name"))).single()
            assertNull(unknown.name)
            assertNull(unknown.providerPackage)
            val provider = register(MetadataProvider(null, fail = true))
            val failed = IncomingShareStore(context).review(listOf(uri)).single()
            assertNull(failed.name)
            assertEquals("example.provider", failed.providerPackage)
            assertEquals(0, provider.opens)
        }

    @Test fun `missing unsafe deceptive and oversized names remain unknown`() =
        runBlocking {
            listOf(
                null,
                "",
                ".",
                "..",
                "../private",
                "name\\escape",
                "line\nbreak",
                "reversed\u202Etxt",
                "x".repeat(256),
            ).forEach { name ->
                register(MetadataProvider(name))
                assertNull(IncomingShareStore(context).review(listOf(uri)).single().name)
            }
            register(MetadataProvider("x".repeat(255)))
            assertEquals(
                255,
                IncomingShareStore(context)
                    .review(listOf(uri))
                    .single()
                    .name
                    ?.length,
            )
        }

    @Test fun `review rejects bounds unsafe schemes and own profile authorities before queries`() {
        val provider = register(MetadataProvider("file"))
        val store = IncomingShareStore(context)
        val invalid =
            listOf(
                emptyList(),
                List(101) { uri },
                listOf(Uri.parse("file:///private/file")),
                listOf(Uri.parse("content://${context.packageName}.documents/file")),
                listOf(Uri.parse("content://0@${context.packageName}.vault-export/file")),
            )
        invalid.forEach { sources ->
            assertThrows(IllegalArgumentException::class.java) { runBlocking { store.review(sources) } }
        }
        assertEquals(0, provider.queries)
        assertEquals(0, provider.opens)
    }

    @Test fun `metadata timeout is bounded even when provider ignores interruption`() =
        runBlocking {
            val provider = register(MetadataProvider("late.jpg", block = true))
            try {
                val review = async { reviewIncomingShareMetadata(context, listOf(uri), timeoutMillis = 1_000) }
                val result = withTimeout(2_000) { review.await() }
                assertNull(result.single().name)
                assertTrue(provider.started.await(1, TimeUnit.SECONDS))
                // The occupied worker cannot accumulate new queued provider queries.
                assertNull(withTimeout(2_000) { reviewIncomingShareMetadata(context, listOf(uri), 100) }.single().name)
                assertEquals(1, provider.queries)
                assertEquals(0, provider.opens)
            } finally {
                provider.release.countDown()
                assertTrue(provider.finished.await(2, TimeUnit.SECONDS))
            }
        }

    @Test fun `cancelling metadata review cancels provider signal without staging bytes`() =
        runBlocking {
            val provider = register(MetadataProvider("late.jpg", block = true))
            try {
                val review =
                    async(kotlinx.coroutines.Dispatchers.Default) { IncomingShareStore(context).review(listOf(uri)) }
                assertTrue(provider.started.await(2, TimeUnit.SECONDS))
                withTimeout(2_000) { review.cancelAndJoin() }
                withTimeout(2_000) {
                    while (provider.signal?.isCanceled != true) kotlinx.coroutines.delay(10)
                }
                assertEquals(0, provider.opens)
                assertFalse(File(context.noBackupFilesDir, "incoming-shares").exists())
            } finally {
                provider.release.countDown()
                assertTrue(provider.finished.await(2, TimeUnit.SECONDS))
            }
        }

    private fun register(provider: MetadataProvider): MetadataProvider {
        val info =
            ProviderInfo().apply {
                authority = "review.test"
                packageName = "example.provider"
                name = MetadataProvider::class.java.name
            }
        shadowOf(context.packageManager).installPackage(
            PackageInfo().apply {
                packageName = "example.provider"
                providers = arrayOf(info)
            },
        )
        provider.attachInfo(context, info)
        ShadowContentResolver.registerProviderInternal("review.test", provider)
        return provider
    }

    private class MetadataProvider(
        private val name: String?,
        private val fail: Boolean = false,
        private val block: Boolean = false,
    ) : ContentProvider() {
        var queries = 0
        var opens = 0
        var projection: List<String>? = null
        var signal: CancellationSignal? = null
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val finished = CountDownLatch(1)

        override fun onCreate() = true

        override fun getType(uri: Uri): String? = null

        override fun openFile(
            uri: Uri,
            mode: String,
        ): ParcelFileDescriptor {
            opens++
            error("Review must not open content")
        }

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            selectionArgs: Array<out String>?,
            sortOrder: String?,
            cancellationSignal: CancellationSignal?,
        ): MatrixCursor {
            signal = cancellationSignal
            return query(uri, projection, selection, selectionArgs, sortOrder)
        }

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            selectionArgs: Array<out String>?,
            sortOrder: String?,
        ): MatrixCursor {
            queries++
            this.projection = projection?.toList()
            started.countDown()
            try {
                if (fail) throw SecurityException("Synthetic metadata denial")
                if (block) awaitReleaseIgnoringInterruption()
                return MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME)).apply { addRow(arrayOf(name)) }
            } finally {
                finished.countDown()
            }
        }

        private fun awaitReleaseIgnoringInterruption() {
            while (release.count > 0) {
                try {
                    release.await()
                } catch (_: InterruptedException) {
                    // Deliberately model a provider that ignores cancellation.
                }
            }
        }

        override fun insert(
            uri: Uri,
            values: ContentValues?,
        ): Uri? = error("No writes")

        override fun delete(
            uri: Uri,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = error("No writes")

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = error("No writes")
    }
}
