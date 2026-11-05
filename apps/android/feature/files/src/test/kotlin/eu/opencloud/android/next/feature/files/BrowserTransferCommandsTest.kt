package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

class BrowserTransferCommandsTest {
    @Test fun `individual decisions preserve exact backend flags and admitted transfer snapshot`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                val transfer = transfer()
                for (decision in ConflictDecision.entries) {
                    fixture.ui.onMain { fixture.commands.resolveConflict(transfer, decision) }
                    val command = fixture.nextCommand()
                    assertEquals(transfer, command.transfer)
                    assertEquals(if (decision == ConflictDecision.CANCEL) "cancel" else "retry", command.action)
                    assertEquals(decision == ConflictDecision.REPLACE, command.overwrite)
                    assertEquals(decision == ConflictDecision.KEEP_BOTH, command.keepBoth)
                    command.result.complete(Unit)
                    fixture.ui.idle()
                }
                assertNull(fixture.ui.state.value.error)
            }
        }

    @Test fun `bulk cancel admits only matching account upload conflicts and gates repeated decisions immediately`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.ui.onMain {
                    fixture.commands.resolveConflict(transfer().copy(accountId = "b"), ConflictDecision.REPLACE)
                    fixture.ui.state.value =
                        fixture.ui.state.value.copy(
                            error = "Previous error",
                            transfers =
                                listOf(
                                    transfer().copy(accountId = "b"),
                                    transfer().copy(direction = TransferDirection.DOWNLOAD.name),
                                    transfer().copy(state = TransferState.FAILED.name),
                                ),
                        )
                    fixture.commands.cancelUploadConflicts()
                }
                fixture.ui.idle()
                assertTrue(fixture.commandsSent.tryReceive().isFailure)
                assertEquals("Previous error", fixture.ui.state.value.error)
                fixture.conflicts()
                fixture.ui.onMain {
                    fixture.commands.cancelUploadConflicts()
                    assertTrue(fixture.ui.state.value.bulkConflictCancelling)
                    assertNull(fixture.ui.state.value.error)
                    fixture.commands.cancelUploadConflicts()
                    fixture.commands.resolveConflict(transfer(), ConflictDecision.CANCEL)
                }
                val command = fixture.nextCommand()
                assertEquals("bulk", command.action)
                assertEquals("a", command.account)
                assertTrue(fixture.commandsSent.tryReceive().isFailure)
                command.result.complete(Unit)
                fixture.ui.idle()
                assertFalse(fixture.ui.state.value.bulkConflictCancelling)
                assertNull(fixture.ui.state.value.error)
            }
        }

    @Test fun `old bulk completion cannot clear a new same-account epoch operation or replace its error`() =
        runBlocking {
            for (oldFails in listOf(false, true)) {
                Fixture().use { fixture ->
                    fixture.ui.account("a")
                    fixture.conflicts()
                    fixture.ui.onMain { fixture.commands.cancelUploadConflicts() }
                    val old = fixture.nextCommand()
                    val oldJob = fixture.ui.jobs().single()
                    fixture.ui.account("b")
                    fixture.ui.account("a")
                    fixture.conflicts()
                    fixture.ui.onMain { fixture.commands.cancelUploadConflicts() }
                    val current = fixture.nextCommand()
                    fixture.ui.onMain {
                        fixture.ui.state.value =
                            fixture.ui.state.value
                                .copy(error = "Current error")
                    }
                    if (oldFails) {
                        old.result.completeExceptionally(IllegalStateException("synthetic old failure"))
                    } else {
                        old.result.complete(Unit)
                    }
                    withTimeout(5000) { oldJob.join() }
                    assertTrue(fixture.ui.state.value.bulkConflictCancelling)
                    assertEquals("Current error", fixture.ui.state.value.error)
                    assertEquals(0, fixture.mappedFailures)
                    current.result.complete(Unit)
                    fixture.ui.idle()
                    assertFalse(fixture.ui.state.value.bulkConflictCancelling)
                    assertEquals("Current error", fixture.ui.state.value.error)
                    assertTrue(fixture.commandsSent.tryReceive().isFailure)
                }
            }
        }

    @Test fun `individual failure remains fenced after account roundtrip while accepted backend runs once`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.ui.onMain { fixture.commands.resolveConflict(transfer(), ConflictDecision.KEEP_BOTH) }
                val command = fixture.nextCommand()
                fixture.ui.account("b")
                fixture.ui.account("a")
                command.result.completeExceptionally(IllegalStateException("synthetic failure"))
                fixture.ui.idle()
                assertNull(fixture.ui.state.value.error)
                assertEquals(0, fixture.mappedFailures)
                assertTrue(fixture.commandsSent.tryReceive().isFailure)
            }
        }

    @Test fun `same epoch bulk failure releases displayed gate and maps failure once`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.conflicts()
                fixture.ui.onMain { fixture.commands.cancelUploadConflicts() }
                fixture.nextCommand().result.completeExceptionally(IllegalStateException("synthetic failure"))
                fixture.ui.idle()
                assertFalse(fixture.ui.state.value.bulkConflictCancelling)
                assertEquals("Transfer failed", fixture.ui.state.value.error)
                assertEquals(1, fixture.mappedFailures)
                assertTrue(fixture.commandsSent.tryReceive().isFailure)
            }
        }

    @Test fun `cancelled bulk completion cannot publish or silently replay`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.conflicts()
                fixture.ui.onMain { fixture.commands.cancelUploadConflicts() }
                val command = fixture.nextCommand()
                val job = fixture.ui.jobs().single()
                job.cancel()
                command.result.complete(Unit)
                withTimeout(5000) { job.join() }
                assertTrue(job.isCancelled)
                assertNull(fixture.ui.state.value.error)
                assertEquals(0, fixture.mappedFailures)
                // As before, scope cancellation does not manufacture a backend completion or UI reset.
                assertTrue(fixture.ui.state.value.bulkConflictCancelling)
                assertTrue(fixture.commandsSent.tryReceive().isFailure)
            }
        }

    @Test fun `no account or blank account cannot cancel conflicts`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.onMain {
                    fixture.commands.resolveConflict(transfer(), ConflictDecision.CANCEL)
                    fixture.commands.cancelUploadConflicts()
                }
                fixture.ui.account("")
                fixture.ui.onMain {
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(transfers = listOf(transfer().copy(accountId = "")))
                    fixture.commands.cancelUploadConflicts()
                }
                fixture.ui.idle()
                assertTrue(fixture.commandsSent.tryReceive().isFailure)
            }
        }

    private class Fixture : AutoCloseable {
        val ui = BrowserCommandTestFixture()
        val commandsSent = Channel<Command>(Channel.UNLIMITED)
        private val pending = CopyOnWriteArrayList<Command>()
        var mappedFailures = 0
        val commands =
            BrowserTransferCommands(
                scope = ui.scope,
                accountContext = ui.context,
                state = ui.state,
                backend =
                    object : BrowserTransferBackend {
                        override suspend fun retryConflict(
                            transfer: TransferEntity,
                            overwrite: Boolean,
                            keepBoth: Boolean,
                        ) = execute(Command("retry", transfer.accountId, transfer, overwrite, keepBoth))

                        override suspend fun cancelConflict(transfer: TransferEntity) =
                            execute(Command("cancel", transfer.accountId, transfer))

                        override suspend fun cancelUploadConflicts(accountId: String) =
                            execute(Command("bulk", accountId))

                        private suspend fun execute(command: Command) {
                            ui.assertIO()
                            pending += command
                            commandsSent.send(command)
                            withContext(NonCancellable) { command.result.await() }
                        }
                    },
                reduce = ui::reduce,
                failureMessage = {
                    if (it is CancellationException) throw it
                    mappedFailures++
                    "Transfer failed"
                },
                ioDispatcher = ui.io,
            )

        suspend fun conflicts() = ui.onMain { ui.state.value = ui.state.value.copy(transfers = listOf(transfer())) }

        suspend fun nextCommand(): Command = withTimeout(5000) { commandsSent.receive() }

        override fun close() {
            pending.forEach { it.result.complete(Unit) }
            ui.close()
        }
    }

    private class Command(
        val action: String,
        val account: String,
        val transfer: TransferEntity? = null,
        val overwrite: Boolean = false,
        val keepBoth: Boolean = false,
    ) {
        val result = CompletableDeferred<Unit>()
    }

    private companion object {
        fun transfer() =
            TransferEntity(
                id = "transfer",
                accountId = "a",
                spaceId = "space",
                resourceId = null,
                direction = TransferDirection.UPLOAD.name,
                sourceUri = "content://synthetic/file",
                destinationPath = "/file",
                displayName = "File",
                mimeType = null,
                bytesTotal = 7,
                state = TransferState.CONFLICT.name,
                createdAtEpochMillis = 0,
                updatedAtEpochMillis = 0,
            )
    }
}
