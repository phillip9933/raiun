package eu.opencloud.android.next.feature.files

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class IncomingActionTest {
    @Test fun `inner cancellation is propagated without displaying an error`() =
        runBlocking {
            val expected = CancellationException("intake revoked")
            var displayed = false
            var caught = false
            try {
                incomingAction({ throw expected }) { displayed = true }
            } catch (actual: CancellationException) {
                caught = true
                assertSame(expected, actual)
            }
            assertTrue(caught)
            assertFalse(displayed)
        }

    @Test fun `cancelled provider failure cannot publish an error after disposal`() =
        runBlocking {
            var displayed = false
            val job =
                launch {
                    incomingAction({
                        currentCoroutineContext().cancel()
                        throw IOException("provider closed")
                    }) { displayed = true }
                }
            job.join()
            assertTrue(job.isCancelled)
            assertFalse(displayed)
        }

    @Test fun `ordinary intake failure remains visible`() =
        runBlocking {
            val expected = IOException("unavailable provider")
            var displayed: Exception? = null
            incomingAction({ throw expected }) { displayed = it }
            assertSame(expected, displayed)
        }
}
