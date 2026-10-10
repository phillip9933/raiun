package eu.opencloud.android.next.core.sync

import android.content.res.AssetFileDescriptor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Checks Android's real descriptor behavior when a sender leaves a pipe read blocked. */
@RunWith(AndroidJUnit4::class)
class IncomingSharePipeAndroidTest {
    @Test fun cancellingBlockedPipeStopsStagingWithoutPublishing() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = File(context.cacheDir, "share-pipe-${UUID.randomUUID()}")
        val pipe = ParcelFileDescriptor.createPipe()
        val signal = CancellationSignal()
        val cancelled = AtomicBoolean(false)
        val input =
            cancellableAssetInputStream(
                AssetFileDescriptor(pipe[0], 0, AssetFileDescriptor.UNKNOWN_LENGTH),
                signal,
                isStopped = { cancelled.get() },
            )
        val reading = CountDownLatch(1)
        val done = CountDownLatch(1)
        val worker =
            Thread {
                try {
                    stageUploadSource(
                        directory,
                        -1,
                        { input },
                        { Long.MAX_VALUE },
                        minimumFreeBytes = 0,
                        maximumBytes = Long.MAX_VALUE,
                        onReadStart = { reading.countDown() },
                        onReadEnd = {},
                        checkActive = { if (cancelled.get()) throw java.util.concurrent.CancellationException() },
                    )
                } catch (_: Exception) {
                    // Cancellation or a closed pipe must stop publication.
                } finally {
                    done.countDown()
                }
            }.apply { isDaemon = true }
        try {
            worker.start()
            assertTrue(reading.await(3, TimeUnit.SECONDS))
            Thread.sleep(100)
            assertTrue("The provider read should still be blocked", done.count == 1L)
            cancelled.set(true)
            input.close()
            signal.cancel()
            assertTrue("Cancellation must release the guarded pipe read", done.await(3, TimeUnit.SECONDS))
            assertFalse(File(directory, "seal").exists())
            assertFalse(File(directory, "payload").exists())
        } finally {
            runCatching { pipe[1].close() }
            directory.deleteRecursively()
        }
    }

    @Test fun guardedAssetReadPreservesBytesAndDeclaredOffset() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val source =
            File(
                context.cacheDir,
                "share-offset-${UUID.randomUUID()}",
            ).apply { writeText("prefix-payload-tail") }
        val descriptor = ParcelFileDescriptor.open(source, ParcelFileDescriptor.MODE_READ_ONLY)
        val input =
            cancellableAssetInputStream(
                AssetFileDescriptor(descriptor, 7, 7),
                CancellationSignal(),
                isStopped = { false },
            )
        try {
            assertEquals("payload", input.bufferedReader().readText())
        } finally {
            input.close()
            source.delete()
        }
    }
}
