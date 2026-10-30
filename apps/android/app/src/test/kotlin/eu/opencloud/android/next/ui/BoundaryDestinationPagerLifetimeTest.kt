package eu.opencloud.android.next.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.sync.BoundaryDestinationFolder
import eu.opencloud.android.next.core.sync.BoundaryDestinationSnapshot
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream

@RunWith(RobolectricTestRunner::class)
class BoundaryDestinationPagerLifetimeTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test fun lateBuildAfterCloseIsDisposedWithoutClosingSourceOwnedEndpoint() =
        runBlocking<Unit> {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val snapshot = Snapshot("old")
            val source =
                Endpoint {
                    entered.complete(Unit)
                    release.await()
                    snapshot
                }
            val pager = BoundaryDestinationPager(context, Dispatchers.Unconfined)
            val pending = async { pager.open(source, "") {} }
            try {
                withTimeout(5_000) { entered.await() }
                pager.close()
                release.complete(Unit)
                val failure = runCatching { withTimeout(5_000) { pending.await() } }.exceptionOrNull()
                assertTrue(failure is CancellationException)
                assertEquals(1, snapshot.closes)
                assertEquals(0, source.closes)
            } finally {
                release.complete(Unit)
                pager.close()
            }
        }

    @Test fun lateOldPageCannotReplaceOrCloseNewRootInventory() =
        runBlocking<Unit> {
            val entered = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            val old = Snapshot("old", total = 2)
            old.beforePage = { offset ->
                if (offset != 0L) {
                    entered.complete(Unit)
                    release.await()
                }
            }
            val fresh = Snapshot("fresh")
            val pager = BoundaryDestinationPager(context, Dispatchers.Unconfined)
            try {
                val initial = pager.open(Endpoint { old }, "") {}
                val pending = async { pager.page(false, initial.page) {} }
                withTimeout(5_000) { entered.await() }
                val latest = pager.open(Endpoint { fresh }, "") {}
                release.complete(Unit)
                val failure = runCatching { withTimeout(5_000) { pending.await() } }.exceptionOrNull()
                assertTrue(failure is CancellationException)
                assertEquals("fresh", latest.folders.single().id)
                assertEquals(1, old.closes)
                assertEquals(0, fresh.closes)
            } finally {
                release.complete(Unit)
                pager.close()
            }
            assertEquals(1, fresh.closes)
        }

    @Test fun accountOrLockRejectionAtDeliveryDisposesSnapshotAndPublishesNoWindow() =
        runBlocking<Unit> {
            val snapshot = Snapshot("unpublished")
            val pager = BoundaryDestinationPager(context, Dispatchers.Unconfined)
            var checks = 0
            try {
                val failure =
                    runCatching {
                        pager.open(Endpoint { snapshot }, "") {
                            if (++checks == 2) throw OpenCloudException(OpenCloudError.AccessDenied)
                        }
                    }.exceptionOrNull()
                assertTrue(failure is OpenCloudException)
                assertEquals(OpenCloudError.AccessDenied, (failure as OpenCloudException).error)
                assertEquals(1, snapshot.closes)
            } finally {
                pager.close()
            }
        }

    private class Snapshot(
        private val id: String,
        override val totalCount: Long = 1,
    ) : BoundaryDestinationSnapshot {
        constructor(id: String, total: Int) : this(id, total.toLong())

        var closes = 0
        var beforePage: suspend (Long) -> Unit = {}

        override suspend fun page(
            offset: Long,
            limit: Int,
        ): List<BoundaryDestinationFolder> {
            beforePage(offset)
            return listOf(BoundaryDestinationFolder(id, id, id, false))
        }

        override fun close() {
            closes++
        }
    }

    private class Endpoint(
        private val build: suspend () -> BoundaryDestinationSnapshot,
    ) : BoundaryEndpoint,
        Closeable {
        override val identity = "source-owned-session"
        override val encrypted = true
        var closes = 0

        override suspend fun openDestinationFolders(
            context: Context,
            path: String,
        ) = build()

        override suspend fun list(path: String): List<BoundaryEntry> = error("No legacy list in chooser")

        override suspend fun requireUnchanged(entry: BoundaryEntry) = error("No content lease in chooser")

        override suspend fun read(
            entry: BoundaryEntry,
            sink: OutputStream,
        ) = error("No content read in chooser")

        override suspend fun write(
            parent: String,
            name: String,
            source: InputStream,
            size: Long,
            mimeType: String?,
        ): BoundaryEntry = error("No writes in chooser")

        override suspend fun createDirectory(
            parent: String,
            name: String,
        ): BoundaryEntry = error("No writes in chooser")

        override suspend fun delete(entry: BoundaryEntry) = error("No deletion in chooser")

        override fun close() {
            closes++
        }
    }
}
