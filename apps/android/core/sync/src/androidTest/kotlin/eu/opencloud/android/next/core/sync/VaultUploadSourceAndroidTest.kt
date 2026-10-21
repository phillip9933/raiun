package eu.opencloud.android.next.core.sync

import android.content.res.AssetFileDescriptor
import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
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

/** Uses native descriptor polling, including a sender that never writes or closes its pipe. */
@RunWith(AndroidJUnit4::class)
class VaultUploadSourceAndroidTest {
    @Test fun nativeRegularFileReadPreservesBytes() =
        runBlocking {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            val file =
                File(
                    context.cacheDir,
                    "vault-source-${UUID.randomUUID()}",
                ).apply { writeText("native upload bytes") }
            try {
                val actual =
                    withVaultUploadSource({ signal, stopped ->
                        val descriptor = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
                        cancellableAssetInputStream(AssetFileDescriptor(descriptor, 0, file.length()), signal, stopped)
                    }) { input -> input.bufferedReader().readText() }
                assertEquals("native upload bytes", actual)
            } finally {
                file.delete()
            }
        }

    @Test fun cancellingNativeBlockedPipeReturnsBeforeAcceptingUpload() =
        runBlocking {
            val pipe = ParcelFileDescriptor.createPipe()
            val reading = CountDownLatch(1)
            val accepted = AtomicBoolean(false)
            val finished = AtomicBoolean(false)
            val job =
                launch(Dispatchers.IO) {
                    try {
                        withVaultUploadSource({ signal, stopped ->
                            cancellableAssetInputStream(
                                AssetFileDescriptor(pipe[0], 0, AssetFileDescriptor.UNKNOWN_LENGTH),
                                signal,
                                stopped,
                            )
                        }) { input ->
                            reading.countDown()
                            input.read()
                            accepted.set(true)
                        }
                    } finally {
                        finished.set(true)
                    }
                }
            try {
                assertTrue(reading.await(3, TimeUnit.SECONDS))
                delay(100)
                assertFalse("An unwritten live pipe must still be waiting", finished.get())
                job.cancel()
                withTimeout(3_000) { job.join() }
                assertTrue(finished.get())
                assertFalse("Cancelled source bytes must never be accepted", accepted.get())
            } finally {
                job.cancel()
                runCatching { pipe[0].close() }
                runCatching { pipe[1].close() }
            }
        }
}
