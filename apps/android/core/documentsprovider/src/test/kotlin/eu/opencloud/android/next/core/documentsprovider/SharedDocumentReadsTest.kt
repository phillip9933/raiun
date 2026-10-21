package eu.opencloud.android.next.core.documentsprovider

import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import eu.opencloud.android.next.core.sync.SharedDownloadFile
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.FileNotFoundException
import java.io.IOException
import java.util.concurrent.Semaphore

@RunWith(RobolectricTestRunner::class)
class SharedDocumentReadsTest {
    private val request = SharedDownloadRequest("a", "s", "scope", SharedDownloadFile("f", "/f", 1, "\"v1\""))

    @Test fun liveReaderHoldsSlotUntilCloseAndCancellationRevokesIt() =
        runBlocking {
            val slots = Semaphore(1)
            var closes = 0
            var closed = false
            lateinit var callback: SharedReadDescriptor
            val manager =
                SharedDocumentReads({
                    SharedReadSource(1, { _, size ->
                        check(!closed)
                        ByteArray(size)
                    }, {
                        closed = true
                        closes++
                    })
                }, {
                    callback = it
                    pipe()
                }, slots)
            val signal = CancellationSignal()
            val descriptor = manager.open(request, signal)
            try {
                assertEquals(0, slots.availablePermits())
                assertThrows(FileNotFoundException::class.java) { runBlocking { manager.open(request, null) } }
                signal.cancel()
                assertThrows(ErrnoException::class.java) { callback.onGetSize() }
                callback.onRelease()
                assertEquals(1, closes)
                assertEquals(1, slots.availablePermits())
            } finally {
                descriptor.close()
                callback.onRelease()
            }
        }

    @Test fun failedDescriptorCreationClosesPreparedSource() =
        runBlocking {
            val slots = Semaphore(1)
            var closes = 0
            val manager =
                SharedDocumentReads({ SharedReadSource(1, { _, size -> ByteArray(size) }, { closes++ }) }, {
                    throw IOException("creation failed")
                }, slots)
            assertThrows(IOException::class.java) { runBlocking { manager.open(request, null) } }
            assertEquals(1, closes)
            assertEquals(1, slots.availablePermits())
        }

    @Test fun cancellationInterruptsPreparationAndReleasesAdmission() =
        runBlocking {
            val slots = Semaphore(1)
            val entered = CompletableDeferred<Unit>()
            val cleaning = CompletableDeferred<Unit>()
            val finishCleanup = CompletableDeferred<Unit>()
            val signal = CancellationSignal()
            val manager =
                SharedDocumentReads({
                    entered.complete(Unit)
                    try {
                        awaitCancellation()
                    } finally {
                        withContext(NonCancellable) {
                            cleaning.complete(Unit)
                            finishCleanup.await()
                        }
                    }
                }, { pipe() }, slots)
            val opening = async { manager.open(request, signal) }
            withTimeout(5_000) { entered.await() }
            signal.cancel()
            withTimeout(5_000) { cleaning.await() }
            try {
                assertEquals(0, slots.availablePermits())
            } finally {
                finishCleanup.complete(Unit)
            }
            assertThrows(CancellationException::class.java) { runBlocking { withTimeout(5_000) { opening.await() } } }
            assertEquals(1, slots.availablePermits())
        }

    @Test fun cancellationDuringDescriptorCreationClosesUndeliveredDescriptor() =
        runBlocking {
            val slots = Semaphore(1)
            val signal = CancellationSignal()
            var closes = 0
            var descriptor: ParcelFileDescriptor? = null
            val manager =
                SharedDocumentReads({ SharedReadSource(1, { _, size -> ByteArray(size) }, { closes++ }) }, {
                    pipe().also {
                        descriptor = it
                        signal.cancel()
                    }
                }, slots)
            assertThrows(CancellationException::class.java) { runBlocking { manager.open(request, signal) } }
            assertEquals(1, closes)
            assertEquals(1, slots.availablePermits())
            assertThrows(IllegalStateException::class.java) { checkNotNull(descriptor).fd }
            Unit
        }

    private fun pipe(): ParcelFileDescriptor {
        val descriptors = ParcelFileDescriptor.createPipe()
        descriptors[1].close()
        return descriptors[0]
    }
}
