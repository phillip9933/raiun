package eu.opencloud.android.next.feature.files

import android.app.Application
import android.net.Uri
import eu.opencloud.android.next.core.database.FolderBackupEntity
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
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.CopyOnWriteArrayList

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [28], application = Application::class)
class BrowserBackupCommandsTest {
    @Test fun `creation reads metadata on Main then saves captured account once across account roundtrip`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.ui.onMain { fixture.commands.saveBackup(source, draft.copy(destinationPath = "")) }
                val save = fixture.nextSave()
                assertEquals(listOf("metadata", "save"), fixture.events)
                assertEquals("a", save.backup.accountId)
                assertEquals("/Camera Uploads", save.backup.destinationPath)
                assertEquals("Selected folder", save.backup.sourceDisplayName)
                assertTrue(save.backup.deleteAfterUpload)
                fixture.ui.account("b")
                fixture.ui.account("a")
                save.result.complete(Unit)
                fixture.ui.idle()
                assertNull(fixture.ui.state.value.message)
                assertNull(fixture.ui.state.value.error)
                assertTrue(fixture.saves.tryReceive().isFailure)
            }
        }

    @Test fun `update metadata stays on IO and source reselection clears unsafe scan and deletion state`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.metadataOnMain = false
                fixture.ui.account("a")
                val original = backup()
                fixture.ui.onMain {
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(backups = listOf(original))
                }
                fixture.ui.onMain {
                    fixture.commands.completeBackupSourceSelection(
                        "a",
                        original.id,
                        backupSourceSelectionFingerprint(original),
                        draft.copy(spaceId = null, destinationPath = "/New", enabled = false),
                        source,
                    )
                }
                val save = fixture.nextSave()
                val updated = save.backup
                assertEquals(listOf("metadata", "save"), fixture.events)
                assertEquals(original.id, updated.id)
                assertEquals(original.accountId, updated.accountId)
                assertEquals(original.spaceId, updated.spaceId)
                assertEquals(source.toString(), updated.sourceTreeUri)
                assertEquals("Selected folder", updated.sourceDisplayName)
                assertEquals("/New", updated.destinationPath)
                assertFalse(updated.deleteAfterUpload)
                assertFalse(updated.enabled)
                assertEquals(0L, updated.lastSafeScanEpochMillis)
                save.result.complete(Unit)
                fixture.ui.idle()
            }
        }

    @Test fun `picker rejects changed removed and foreign pairs before metadata or backend work`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                val original = backup()
                val fingerprint = backupSourceSelectionFingerprint(original)
                fixture.ui.onMain {
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(backups = listOf(original.copy(enabled = false)))
                    fixture.commands.completeBackupSourceSelection("a", original.id, fingerprint, draft, source)
                    fixture.commands.completeBackupSourceSelection("b", original.id, fingerprint, draft, source)
                    fixture.commands.completeBackupSourceSelection(null, null, null, draft, source)
                    fixture.commands.updateBackup(original.copy(accountId = "b"), draft, source)
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(backups = emptyList())
                    fixture.commands.completeBackupSourceSelection("a", original.id, fingerprint, draft, source)
                }
                fixture.ui.idle()
                assertTrue(fixture.events.isEmpty())
            }
        }

    @Test fun `scan cursor changes do not invalidate picker fingerprint but update without reselection keeps source`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.metadataOnMain = false
                fixture.ui.account("a")
                val original = backup()
                fixture.ui.onMain {
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(backups = listOf(original.copy(lastSafeScanEpochMillis = 456)))
                    fixture.commands.completeBackupSourceSelection(
                        "a",
                        original.id,
                        backupSourceSelectionFingerprint(original),
                        draft,
                        source,
                    )
                }
                fixture.nextSave().result.complete(Unit)
                fixture.ui.idle()
                fixture.ui.onMain { fixture.commands.updateBackup(original, draft) }
                val save = fixture.nextSave()
                assertEquals(original.sourceTreeUri, save.backup.sourceTreeUri)
                assertEquals(original.sourceDisplayName, save.backup.sourceDisplayName)
                assertEquals(0L, save.backup.lastSafeScanEpochMillis)
                assertFalse(save.backup.deleteAfterUpload)
                assertEquals(listOf("metadata", "save", "save"), fixture.events)
                save.result.complete(Unit)
                fixture.ui.idle()
            }
        }

    @Test fun `late update failure cannot overwrite replacement epoch error`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.ui.onMain { fixture.commands.updateBackup(backup(), draft) }
                val save = fixture.nextSave()
                fixture.ui.account("b")
                fixture.ui.account("a")
                fixture.ui.onMain {
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(error = "Current error")
                }
                save.result.completeExceptionally(IllegalStateException("synthetic details"))
                fixture.ui.idle()
                assertEquals("Current error", fixture.ui.state.value.error)
                assertEquals(0, fixture.mappedFailures)
            }
        }

    @Test fun `cancelled save does not publish success or replay after noncooperative backend completion`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.ui.onMain { fixture.commands.saveBackup(source, draft) }
                val save = fixture.nextSave()
                val job = fixture.ui.jobs().single()
                job.cancel()
                save.result.complete(Unit)
                withTimeout(5000) { job.join() }
                assertTrue(job.isCancelled)
                assertNull(fixture.ui.state.value.message)
                assertNull(fixture.ui.state.value.error)
                assertEquals(0, fixture.mappedFailures)
                assertTrue(fixture.saves.tryReceive().isFailure)
            }
        }

    @Test fun `delete forgets only captured diagnostics after deletion completes even if displayed backups change`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                val original = backup()
                fixture.ui.onMain {
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(backups = listOf(original))
                    fixture.commands.deleteBackup(original.id)
                }
                val delete = withTimeout(5000) { fixture.deletes.receive() }
                assertEquals(original.id, delete)
                assertTrue(fixture.forgotten.isEmpty())
                fixture.ui.account("b")
                fixture.deleteResult.complete(Unit)
                fixture.ui.idle()
                assertEquals(listOf(original), fixture.forgotten)
                assertEquals(listOf("delete", "forget"), fixture.events)
            }
        }

    @Test fun `no account or missing destination cannot create and scan remains an explicit command`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.onMain { fixture.commands.saveBackup(source, draft) }
                fixture.ui.account("a")
                fixture.ui.onMain { fixture.commands.saveBackup(source, draft.copy(spaceId = null)) }
                fixture.ui.idle()
                assertTrue(fixture.events.isEmpty())
                fixture.ui.onMain { fixture.commands.scanBackupsNow() }
                assertEquals(listOf("scan"), fixture.events)
            }
        }

    @Test fun `current creation success and failure update only their existing presentation fields`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.ui.onMain { fixture.commands.saveBackup(source, draft) }
                fixture.nextSave().result.complete(Unit)
                fixture.ui.idle()
                assertEquals("Configured", fixture.ui.state.value.message)
                fixture.ui.onMain { fixture.commands.saveBackup(source, draft) }
                fixture.nextSave().result.completeExceptionally(IllegalStateException("synthetic details"))
                fixture.ui.idle()
                assertEquals("Configured", fixture.ui.state.value.message)
                assertEquals("Backup failed", fixture.ui.state.value.error)
                assertEquals(1, fixture.mappedFailures)
            }
        }

    @Test fun `cancellation during deletion cannot forget diagnostics before backend confirmation`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.ui.account("a")
                fixture.ui.onMain {
                    fixture.ui.state.value =
                        fixture.ui.state.value
                            .copy(backups = listOf(backup()))
                    fixture.commands.deleteBackup("pair")
                }
                withTimeout(5000) { fixture.deletes.receive() }
                val job = fixture.ui.jobs().single()
                job.cancel()
                withTimeout(5000) { job.join() }
                assertTrue(job.isCancelled)
                assertTrue(fixture.forgotten.isEmpty())
                assertEquals(listOf("delete"), fixture.events)
            }
        }

    private class Fixture : AutoCloseable {
        val ui = BrowserCommandTestFixture()
        val saves = Channel<Save>(Channel.UNLIMITED)
        val deletes = Channel<String>(Channel.UNLIMITED)
        val deleteResult = CompletableDeferred<Unit>()
        val forgotten = CopyOnWriteArrayList<FolderBackupEntity>()
        val events = CopyOnWriteArrayList<String>()
        private val pending = CopyOnWriteArrayList<Save>()
        var metadataOnMain = true
        var mappedFailures = 0
        val commands =
            BrowserBackupCommands(
                scope = ui.scope,
                accountContext = ui.context,
                state = ui.state,
                backend =
                    object : BrowserBackupBackend {
                        override fun sourceDirectoryName(treeUri: Uri): String {
                            if (metadataOnMain) ui.assertMain() else ui.assertIO()
                            assertEquals(source, treeUri)
                            events += "metadata"
                            return "Selected folder"
                        }

                        override suspend fun saveBackup(backup: FolderBackupEntity) {
                            ui.assertIO()
                            events += "save"
                            val save = Save(backup)
                            pending += save
                            saves.send(save)
                            // Account admission must still fence a storage operation completing after cancellation.
                            withContext(NonCancellable) { save.result.await() }
                        }

                        override suspend fun deleteBackup(id: String) {
                            ui.assertIO()
                            events += "delete"
                            deletes.send(id)
                            deleteResult.await()
                        }

                        override fun forgetDiagnostics(backup: FolderBackupEntity) {
                            ui.assertIO()
                            events += "forget"
                            forgotten += backup
                        }

                        override fun scanBackupsNow() {
                            ui.assertMain()
                            events += "scan"
                        }
                    },
                reduce = ui::reduce,
                failureMessage = {
                    if (it is CancellationException) throw it
                    mappedFailures++
                    "Backup failed"
                },
                configuredMessage = { "Configured" },
                ioDispatcher = ui.io,
            )

        suspend fun nextSave(): Save = withTimeout(5000) { saves.receive() }

        override fun close() {
            pending.forEach { it.result.complete(Unit) }
            deleteResult.complete(Unit)
            ui.close()
        }
    }

    private class Save(
        val backup: FolderBackupEntity,
    ) {
        val result = CompletableDeferred<Unit>()
    }

    private companion object {
        val source: Uri = Uri.parse("content://synthetic/tree/primary%3ASelected")
        val draft = BackupDraft("/Backup", "ALL", true, false, true, spaceId = "space")

        fun backup() =
            FolderBackupEntity(
                "pair",
                "a",
                "space",
                "content://synthetic/tree/primary%3AOriginal",
                "Original folder",
                "/Backup",
                "ALL",
                true,
                false,
                true,
                lastSafeScanEpochMillis = 123,
            )
    }
}
