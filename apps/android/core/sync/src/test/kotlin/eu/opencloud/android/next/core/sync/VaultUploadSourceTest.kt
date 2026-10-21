package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.InputStream
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [31])
class VaultUploadSourceTest {
    @Test fun `cancellation closes blocked input before partial bytes can be accepted`() =
        runBlocking {
            val source = BlockedInput()
            val accepted = AtomicBoolean(false)
            val job =
                launch(Dispatchers.IO) {
                    withVaultUploadSource({ _, _ -> source }) { input ->
                        input.read()
                        accepted.set(true)
                    }
                }
            assertTrue(source.readStarted.await(5, TimeUnit.SECONDS))
            job.cancel()
            withTimeout(5_000) { job.join() }
            assertTrue(source.closed.get())
            assertFalse(accepted.get())
        }

    @Test fun `cancellation during provider opening closes late descriptor`() =
        runBlocking {
            val opening = CountDownLatch(1)
            val release = CountDownLatch(1)
            val source = BlockedInput()
            val accepted = AtomicBoolean(false)
            val job =
                launch(Dispatchers.IO) {
                    withVaultUploadSource({ signal, _ ->
                        signal.setOnCancelListener { release.countDown() }
                        opening.countDown()
                        check(release.await(5, TimeUnit.SECONDS))
                        source
                    }) { accepted.set(true) }
                }
            assertTrue(opening.await(5, TimeUnit.SECONDS))
            job.cancel()
            withTimeout(5_000) { job.join() }
            assertTrue(source.closed.get())
            assertFalse(accepted.get())
        }

    private class BlockedInput : InputStream() {
        val readStarted = CountDownLatch(1)
        val closed = AtomicBoolean(false)
        private val released = CountDownLatch(1)

        override fun read(): Int {
            readStarted.countDown()
            check(released.await(5, TimeUnit.SECONDS))
            return -1
        }

        override fun close() {
            closed.set(true)
            released.countDown()
        }
    }
}
