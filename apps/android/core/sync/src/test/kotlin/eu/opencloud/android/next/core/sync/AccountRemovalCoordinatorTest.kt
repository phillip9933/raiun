package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class AccountRemovalCoordinatorTest {
    @Test fun failedCleanupRetainsTombstoneAndRestartRepeatsIdempotentStagesBeforeAcknowledgement() =
        runTest {
            var pending = true
            val files = mutableSetOf("a-key", "a-file", "b-key", "b-file")
            var fail = true
            val stages: List<suspend () -> Unit> =
                listOf(
                    { files.remove("a-key") },
                    {
                        if (fail) throw IOException("synthetic cleanup failure")
                        files.remove("a-file")
                    },
                )
            try {
                completeAccountRemoval(stages) { pending = false }
            } catch (_: IOException) {
                // Simulates process loss before a retry; no completed-stage state is required.
            }
            assertTrue(pending)
            assertEquals(setOf("a-file", "b-key", "b-file"), files)
            fail = false
            completeAccountRemoval(stages) { pending = false }
            assertFalse(pending)
            assertEquals(setOf("b-key", "b-file"), files)
        }

    @Test fun cancellationNeverAcknowledgesRemovalAndRetryCompletes() =
        runTest {
            var pending = true
            var cancelled = false
            try {
                completeAccountRemoval(listOf({ throw CancellationException() })) { pending = false }
            } catch (_: CancellationException) {
                cancelled = true
            }
            assertTrue(cancelled)
            assertTrue(pending)
            completeAccountRemoval(emptyList()) { pending = false }
            assertFalse(pending)
        }
}
