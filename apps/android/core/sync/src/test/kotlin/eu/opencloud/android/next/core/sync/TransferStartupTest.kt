package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransferStartupTest {
    @Test fun `failed file operation recovery does not strand transfers or cleanup`() =
        runTest {
            val recovered = mutableListOf<StartupRecoveryStep>()
            val failed = mutableListOf<StartupRecoveryStep>()
            val stages =
                linkedMapOf<StartupRecoveryStep, suspend () -> Unit>(
                    StartupRecoveryStep.FILE_OPERATIONS to { error("synthetic private metadata") },
                    StartupRecoveryStep.TRANSFERS to { recovered.add(StartupRecoveryStep.TRANSFERS) },
                    StartupRecoveryStep.CACHE_CLEANUP to { recovered.add(StartupRecoveryStep.CACHE_CLEANUP) },
                )
            recoverStartupStages(stages, failed::add)
            assertEquals(listOf(StartupRecoveryStep.FILE_OPERATIONS), failed)
            assertEquals(listOf(StartupRecoveryStep.TRANSFERS, StartupRecoveryStep.CACHE_CLEANUP), recovered)
        }

    @Test fun `cancellation stops later recovery without reporting a failure`() =
        runTest {
            var recovered = false
            var reported = false
            var cancelled = false
            val stages =
                linkedMapOf<StartupRecoveryStep, suspend () -> Unit>(
                    StartupRecoveryStep.FILE_OPERATIONS to { throw CancellationException() },
                    StartupRecoveryStep.TRANSFERS to { recovered = true },
                )
            try {
                recoverStartupStages(stages) { reported = true }
            } catch (_: CancellationException) {
                cancelled = true
            }
            assertTrue(cancelled)
            assertFalse(recovered)
            assertFalse(reported)
        }
}
