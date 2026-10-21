package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.TransferHttpException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class TusSessionTest {
    @Test fun `expired addresses are cleared before replacement and valid addresses resume`() =
        runTest {
            for (status in listOf(404, 410)) {
                val events = mutableListOf<String>()
                val session =
                    openTusSession("old", offset = { throw TransferHttpException(status) }, create = {
                        events += "create"
                        "new"
                    }, reset = { events += "reset" })
                assertEquals(listOf("reset", "create"), events)
                assertEquals(TusSession("new", 0), session)
            }
            assertEquals(
                TusSession("valid", 8),
                openTusSession("valid", { 8 }, { error("must not create") }, {
                    error("must not reset")
                }),
            )
        }

    @Test fun `authentication readiness and cancellation never discard resumable progress`() =
        runTest {
            val failures = listOf(TransferHttpException(401), TransferHttpException(425, 20), CancellationException())
            for (failure in failures) {
                try {
                    openTusSession(
                        "valid",
                        { throw failure },
                        { error("must not create") },
                        { error("must not reset") },
                    )
                    org.junit.Assert.fail("The original failure must propagate")
                } catch (actual: Exception) {
                    assertSame(failure, actual)
                }
            }
        }

    @Test fun `failed durable reset cannot create another upload`() =
        runTest {
            val failure = java.io.IOException("disk unavailable")
            try {
                openTusSession(
                    "expired",
                    { throw TransferHttpException(410) },
                    { error("must not create") },
                    { throw failure },
                )
                org.junit.Assert.fail("Reset failure must propagate")
            } catch (actual: java.io.IOException) {
                assertSame(failure, actual)
            }
        }
}
