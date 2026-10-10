package eu.opencloud.android.next.ui

import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.sync.VaultExternalCopyStore
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowContentResolver
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
@Suppress("LargeClass") // Transfer and handoff races share one isolated session fixture.
class VaultViewModelTransferTest {
    @After fun resetMainDispatcher() = Dispatchers.resetMain()

    @Test fun pickerReturnAfterStopResumesUploadAfterReunlockExactlyOnce() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val context = ApplicationProvider.getApplicationContext<Application>()
            val source = File(context.cacheDir, "vault-upload-source.txt").apply { writeText("hello") }
            UploadProvider(source).also {
                it.attachInfo(RuntimeEnvironment.getApplication(), ProviderInfo().apply { authority = AUTHORITY })
                ShadowContentResolver.registerProviderInternal(AUTHORITY, it)
            }
            val repository = TestRepository(mutableListOf(TestSession(identity), TestSession(identity)))
            val viewModel = newViewModel(context, repository)
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )
            viewModel.unlock("password".toCharArray())
            advanceUntilIdle()
            var launches = 0
            viewModel.prepareUpload { launches++ }
            advanceUntilIdle()
            assertEquals(1, launches)
            viewModel.lock()
            viewModel.acceptUploadUri(Uri.parse("content://$AUTHORITY/source"))
            viewModel.unlock("password".toCharArray())
            advanceUntilIdle()
            assertEquals(
                "mode=${viewModel.state.value.mode}, error=${viewModel.state.value.error}",
                1,
                repository.uploadCalls,
            )
            assertEquals("hello", repository.uploadedText)
            assertFalse(viewModel.state.value.loading)
            viewModel.leaveRoute()
            source.delete()
        }

    @Test fun concurrentPreparationLaunchesOnlyOnePicker() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var encoder: Continuation<String>? = null
            val session = TestSession(identity, encodeBlock = { suspendCoroutine { encoder = it } })
            val viewModel =
                newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(session)))
            enterAndUnlock(viewModel)
            var launches = 0
            viewModel.prepareUpload { launches++ }
            runCurrent()
            viewModel.prepareUpload { launches++ }
            runCurrent()
            encoder!!.resume("opaque-parent")
            advanceUntilIdle()
            assertEquals(1, launches)
            viewModel.leaveRoute()
        }

    @Test fun largeExportCanInvokePickerLauncher() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val session = TestSession(identity, listOf(fileEntry(size = 64L * 1024 * 1024)))
            val viewModel =
                newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(session)))
            enterAndUnlock(viewModel)
            var launches = 0
            viewModel.prepareExport(
                viewModel.state.value.entries
                    .single()
                    .id,
            ) { launches++ }
            advanceUntilIdle()
            assertEquals(1, launches)
            assertEquals(null, viewModel.state.value.error)
            viewModel.leaveRoute()
        }

    @Test fun pickerReturnDuringLeaseUploadsWithoutAnotherUnlock() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val context = ApplicationProvider.getApplicationContext<Application>()
            val source = File(context.cacheDir, "vault-upload-active.txt").apply { writeText("active") }
            registerUploadProvider(source)
            val repository = TestRepository(mutableListOf(TestSession(identity)))
            val viewModel = newViewModel(context, repository)
            enterAndUnlock(viewModel)
            var launches = 0
            viewModel.prepareUpload { launches++ }
            advanceUntilIdle()
            viewModel.onRouteStopped()
            runCurrent()
            assertTrue(
                viewModel.state.value.entries
                    .isEmpty(),
            )
            viewModel.acceptUploadUri(Uri.parse("content://$AUTHORITY/source"))
            advanceUntilIdle()

            assertEquals(1, launches)
            assertEquals(1, repository.uploadCalls)
            assertEquals("active", repository.uploadedText)
            viewModel.leaveRoute()
            source.delete()
        }

    @Test fun accountChangeDiscardsOutstandingPickerHandoff() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val secondIdentity = identity.copy(accountId = OTHER_ACCOUNT)
            val repository =
                TestRepository(
                    mutableListOf(TestSession(identity), TestSession(secondIdentity)),
                    listOf(location, location.copy(accountId = OTHER_ACCOUNT)),
                )
            val viewModel = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            enterAndUnlock(viewModel)
            viewModel.prepareUpload {}
            advanceUntilIdle()
            viewModel.lock()

            viewModel.enterRoute(OTHER_ACCOUNT)
            advanceUntilIdle()
            viewModel.acceptUploadUri(Uri.parse("content://$AUTHORITY/late"))
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )
            viewModel.unlock("password".toCharArray())
            advanceUntilIdle()

            assertEquals(0, repository.uploadCalls)
            viewModel.leaveRoute()
        }

    @Test fun pickerTimeoutRequiresUnlockAndDoesNotUpload() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = TestRepository(mutableListOf(TestSession(identity)))
            val viewModel = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            enterAndUnlock(viewModel)
            viewModel.prepareUpload {}
            runCurrent()
            viewModel.onRouteStopped()
            advanceTimeBy(VaultPickerLease.DURATION_MS + 1)
            runCurrent()
            assertEquals(VaultRouteMode.UNLOCK, viewModel.state.value.mode)
            viewModel.acceptUploadUri(Uri.parse("content://$AUTHORITY/source"))
            assertEquals(VaultRouteError.TRANSFER_UNLOCK_REQUIRED, viewModel.state.value.error)
            assertEquals(0, repository.uploadCalls)
            viewModel.leaveRoute()
        }

    @Test fun cancellingPickerRestoresListingWithoutStartingUpload() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = TestRepository(mutableListOf(TestSession(identity, listOf(fileEntry()))))
            val viewModel = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            enterAndUnlock(viewModel)
            viewModel.prepareUpload {}
            runCurrent()
            viewModel.onRouteStopped()
            viewModel.acceptUploadUri(null)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, viewModel.state.value.mode)
            assertEquals(1, viewModel.state.value.entries.size)
            assertFalse(viewModel.state.value.loading)
            assertEquals(0, repository.uploadCalls)
            viewModel.leaveRoute()
        }

    @Test fun offlineCatalogDoesNotRequestTheServerAndOfflineSessionsRejectMutations() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity, isOffline = true)
            val repository = TestRepository(mutableListOf(opened))
            val model = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            model.enterRoute(ACCOUNT, offlineCatalog = true)
            runCurrent()
            assertEquals(0, repository.onlineCatalogCalls)
            assertTrue(model.state.value.offlineCatalog)
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            assertTrue(model.state.value.offline)
            var uploadLaunched = false
            model.prepareUpload { uploadLaunched = true }
            model.onEntryAction(
                model.state.value.entries
                    .single()
                    .id,
                VaultEntryAction.DELETE,
                null,
            )
            model.keepDirectoryOffline()
            model.showRootActions()
            advanceUntilIdle()
            assertFalse(uploadLaunched)
            assertFalse(model.state.value.rootActionsVisible)
            assertEquals(null, model.managementTarget(model.state.value.lockRevision))
            var exportLaunched = false
            model.prepareExport(
                model.state.value.entries
                    .single()
                    .id,
            ) { exportLaunched = true }
            runCurrent()
            assertTrue(exportLaunched)
            model.leaveRoute()
        }

    @Test fun directSavedRootOpensAsOfflineWithoutLoadingOnlineCatalog() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val savedRoot = location.copy(offlineOnly = true)
            val offlineSession = TestSession(identity, isOffline = true)
            val repository = TestRepository(mutableListOf(offlineSession))
            val model = newViewModel(ApplicationProvider.getApplicationContext(), repository)

            model.enterRoute(ACCOUNT, initialLocation = savedRoot)
            runCurrent()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertEquals(0, repository.onlineCatalogCalls)

            model.unlock("password".toCharArray())
            advanceUntilIdle()

            assertTrue(model.state.value.offline)
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals(0, repository.onlineCatalogCalls)
            assertEquals(savedRoot, repository.lastUnlockTarget)
            model.leaveRoute()
        }

    @Test fun destinationSelectionRechecksSourceBeforeCopyAndRejectsChangedEtag() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity)
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val source =
                model.state.value.entries
                    .single()
                    .id
            model.loadDestinationFolders("destination")
            advanceUntilIdle()
            opened.entries = listOf(fileEntry().copy(strongETag = "\"changed\""))
            model.onEntryAction(source, VaultEntryAction.COPY, "destination")
            advanceUntilIdle()
            assertEquals(0, opened.copyCalls)
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            model.leaveRoute()
        }

    @Test fun destinationSelectionReissuesSourceLeaseBeforeCopy() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity)
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val source =
                model.state.value.entries
                    .single()
                    .id
            model.loadDestinationFolders("destination")
            advanceUntilIdle()
            model.onEntryAction(source, VaultEntryAction.COPY, "destination")
            model.dismissDestinationPicker()
            advanceUntilIdle()
            assertEquals(1, opened.copyCalls)
            assertEquals("", opened.lastListBeforeCopy)
            assertEquals(null, model.state.value.destinationPickerPath)
            model.leaveRoute()
        }

    @Test fun openWithRejectsChangedSourceBeforeCreatingPlaintextCopy() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity)
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val source =
                model.state.value.entries
                    .single()
                    .id
            opened.entries = listOf(fileEntry().copy(strongETag = "\"changed\""))
            var handoffs = 0
            model.prepareOpenWith(source) { handoffs++ }
            advanceUntilIdle()
            assertEquals(0, handoffs)
            assertEquals(0, opened.downloadCalls)
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            model.leaveRoute()
        }

    @Test fun openWithCannotStartAfterRouteLocks() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity)
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val source =
                model.state.value.entries
                    .single()
                    .id
            model.lock()
            var handoffs = 0
            model.prepareOpenWith(source) { handoffs++ }
            advanceUntilIdle()
            assertEquals(0, handoffs)
            assertEquals(0, opened.downloadCalls)
            model.leaveRoute()
        }

    @Test fun openWithAccountChangeCancelsPartialExportBeforeHandoff() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val context = ApplicationProvider.getApplicationContext<Application>()
            assertTrue(VaultExternalCopyStore.initializeProcess(context, scheduleRetry = false))
            val exportRoot = File(context.noBackupFilesDir, "vault-external-copies")
            val downloadStarted = CompletableDeferred<Unit>()
            val downloadUnwound = CompletableDeferred<Unit>()
            val opened =
                TestSession(identity).apply {
                    downloadBlock = { _, sink, _ ->
                        sink.write("partial plaintext".toByteArray())
                        downloadStarted.complete(Unit)
                        try {
                            suspendCancellableCoroutine { }
                        } finally {
                            downloadUnwound.complete(Unit)
                        }
                    }
                }
            val nextIdentity = identity.copy(accountId = OTHER_ACCOUNT)
            val repository =
                TestRepository(
                    mutableListOf(opened, TestSession(nextIdentity)),
                    listOf(location, location.copy(accountId = OTHER_ACCOUNT)),
                )
            val model = newViewModel(context, repository)
            enterAndUnlock(model)
            var handoffs = 0
            model.prepareOpenWith(
                model.state.value.entries
                    .single()
                    .id,
            ) { handoffs++ }
            runCurrent()
            withContext(Dispatchers.Default) { withTimeout(5_000) { downloadStarted.await() } }
            assertTrue(exportRoot.walkTopDown().any { it.isFile && it.length() > 0L })

            model.enterRoute(OTHER_ACCOUNT)
            runCurrent()
            withContext(Dispatchers.Default) { withTimeout(5_000) { downloadUnwound.await() } }
            val partialRemoved =
                withContext(Dispatchers.Default) {
                    withTimeout(5_000) {
                        withContext(Dispatchers.IO) {
                            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
                            while (exportRoot.listFiles()?.isNotEmpty() == true && System.nanoTime() < deadline) {
                                TimeUnit.MILLISECONDS.sleep(10)
                            }
                            exportRoot.listFiles().isNullOrEmpty()
                        }
                    }
                }
            advanceUntilIdle()

            assertTrue(partialRemoved)
            assertEquals(0, handoffs)
            assertTrue(exportRoot.listFiles().isNullOrEmpty())
            model.leaveRoute()
        }

    @Test fun destinationBrowserIncludesFilesWithPlaintextDisplaySize() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity)
            opened.destinationEntries = listOf(fileEntry(name = "visible.txt", size = 50))
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            model.loadDestinationFolders("destination")
            advanceUntilIdle()
            val file =
                model.state.value.destinationPickerEntries
                    .single()
            assertFalse(file.isFolder)
            assertEquals("visible.txt", file.name)
            assertEquals(2L, file.displaySize)
            model.leaveRoute()
        }

    @Test fun encryptedSizeDisplayExcludesFramingAndRejectsImpossibleLengths() {
        assertEquals(0L, encryptedPlaintextSize(32))
        assertEquals(1L, encryptedPlaintextSize(49))
        assertEquals(65536L, encryptedPlaintextSize(32 + 65552))
        assertEquals(65537L, encryptedPlaintextSize(32 + 65552 + 17))
        assertEquals(null, encryptedPlaintextSize(31))
        assertEquals(null, encryptedPlaintextSize(48))
    }

    @Test fun encryptedConflictNamesSkipOccupiedSiblingsAndTreatFoldersAsWholeNames() {
        assertEquals(
            "report (3).pdf",
            numberedEncryptedName(
                "report.pdf",
                false,
                setOf("report.pdf", "report (1).pdf", "report (2).pdf"),
            ),
        )
        assertEquals("folder.ext (1)", numberedEncryptedName("folder.ext", true, setOf("folder.ext")))
        assertEquals(".hidden (1)", numberedEncryptedName(".hidden", false, setOf(".hidden")))
    }

    @Test fun encryptedCopyConflictWaitsForExplicitDecisionAndPreservesExtension() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity)
            opened.destinationEntries = listOf(fileEntry(), fileEntry().copy(name = "file (1).txt"))
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val source =
                model.state.value.entries
                    .single()
                    .id
            model.onEntryAction(source, VaultEntryAction.COPY, "destination")
            advanceUntilIdle()
            assertEquals(0, opened.copyCalls)
            val proposal = requireNotNull(model.state.value.transferConflict).proposedName
            assertTrue(proposal != fileEntry().name)
            model.resolveTransferConflict(false)
            advanceUntilIdle()
            assertEquals(0, opened.copyCalls)
            model.onEntryAction(source, VaultEntryAction.COPY, "destination")
            advanceUntilIdle()
            model.resolveTransferConflict(true)
            advanceUntilIdle()
            assertEquals(1, opened.copyCalls)
            assertEquals(proposal, opened.copiedName)
            model.leaveRoute()
        }

    @Test fun moveConflictRechecksRacingDestinationAndClearsOnLock() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity)
            opened.destinationEntries = listOf(fileEntry())
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val source =
                model.state.value.entries
                    .single()
                    .id
            model.onEntryAction(source, VaultEntryAction.MOVE, "destination")
            advanceUntilIdle()
            val first = requireNotNull(model.state.value.transferConflict).proposedName
            opened.destinationEntries += fileEntry().copy(name = first)
            model.resolveTransferConflict(true)
            advanceUntilIdle()
            assertEquals(0, opened.moveCalls)
            val second = requireNotNull(model.state.value.transferConflict).proposedName
            assertTrue(first != second)
            model.resolveTransferConflict(true)
            advanceUntilIdle()
            assertEquals(1, opened.moveCalls)
            assertEquals(second, opened.copiedName)
            model.onEntryAction(source, VaultEntryAction.COPY, "destination")
            advanceUntilIdle()
            model.lock()
            model.resolveTransferConflict(true)
            advanceUntilIdle()
            assertEquals(null, model.state.value.transferConflict)
            assertEquals(0, opened.copyCalls)
            model.leaveRoute()
        }

    @Test fun failedOfflinePasswordDoesNotRemoveTheSnapshot() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository =
                TestRepository(
                    mutableListOf(),
                    unlockFailure =
                        eu.opencloud.android.next.core.network.OpenCloudException(
                            eu.opencloud.android.next.core.network.OpenCloudError.AccessDenied,
                        ),
                )
            val model = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            model.enterRoute(ACCOUNT, offlineCatalog = true)
            runCurrent()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("wrong".toCharArray())
            advanceUntilIdle()
            assertEquals(0, repository.offlineRemovalCalls)
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            model.leaveRoute()
        }

    @Test fun onlineAccessDenialRevokesMatchingOfflineCopy() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository =
                TestRepository(
                    mutableListOf(),
                    unlockFailure =
                        eu.opencloud.android.next.core.network.OpenCloudException(
                            eu.opencloud.android.next.core.network.OpenCloudError.AccessDenied,
                        ),
                )
            val model = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            model.enterRoute(ACCOUNT)
            runCurrent()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            assertEquals(1, repository.offlineRemovalCalls)
            model.leaveRoute()
        }

    @Test fun scannerLeaseCannotUploadAfterLockOrIntoAnotherSession() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = TestRepository(mutableListOf(TestSession(identity)))
            val model = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            enterAndUnlock(model)
            val launchTitle =
                model.state.value.selectedTitle
                    .orEmpty()
            val lease = requireNotNull(model.prepareScanner())
            assertEquals(launchTitle, lease.destinationLabel)
            assertTrue(lease.isValid())
            model.lock()
            assertFalse(lease.isValid())
            var rejected = false
            try {
                lease.upload("scan.pdf", byteArrayOf(1).inputStream(), 1, "application/pdf")
            } catch (_: IllegalStateException) {
                rejected = true
            }
            assertTrue(rejected)
            assertEquals(0, repository.uploadCalls)
            model.leaveRoute()
        }

    @Test fun lateThumbnailAfterLockIsWipedAndNeverPublished() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<ByteArray>? = null
            val opened = TestSession(identity, entries = listOf(fileEntry("photo.jpg")))
            opened.previewBlock = { suspendCoroutine { pending = it } }
            val repository = TestRepository(mutableListOf(opened))
            val model = newViewModel(ApplicationProvider.getApplicationContext(), repository)
            enterAndUnlock(model)
            val id =
                model.state.value.entries
                    .single()
                    .id
            val loading = async { model.loadThumbnail(id) }
            runCurrent()
            model.lock()
            val bytes = byteArrayOf(1, 2, 3)
            requireNotNull(pending).resume(bytes)
            advanceUntilIdle()
            assertEquals(null, loading.await())
            assertTrue(bytes.all { it == 0.toByte() })
            model.leaveRoute()
        }

    @Test fun cancelledThumbnailAwaiterWipesLateNonCancellablePreviewBytes() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<ByteArray>? = null
            val opened = TestSession(identity, entries = listOf(fileEntry("photo.jpg")))
            opened.previewBlock = { suspendCoroutine { pending = it } }
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val loading =
                async {
                    model.loadThumbnail(
                        model.state.value.entries
                            .single()
                            .id,
                    )
                }
            runCurrent()
            loading.cancel()
            val bytes = byteArrayOf(9, 8, 7)
            requireNotNull(pending).resume(bytes)
            advanceUntilIdle()
            assertTrue(loading.isCancelled)
            assertTrue(bytes.all { it == 0.toByte() })
            assertEquals(null, model.state.value.preview)
            model.leaveRoute()
        }

    @Test fun unlockedThumbnailIsReturnedOnlyToItsCaller() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity, entries = listOf(fileEntry("photo.jpg")))
            val bytes = byteArrayOf(1, 2, 3)
            opened.previewBlock = { bytes }
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            val result =
                model.loadThumbnail(
                    model.state.value.entries
                        .single()
                        .id,
                )
            assertTrue(result === bytes)
            assertEquals(null, model.state.value.preview)
            result?.fill(0)
            model.leaveRoute()
        }

    @Test fun encryptedTextSaveUsesOriginalIssuedEntryAndWipesOwnedBuffer() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val entry = fileEntry("notes.txt")
            val opened = TestSession(identity, entries = listOf(entry))
            opened.previewBlock = { "original".toByteArray() }
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            model.openPreview(
                model.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()
            val preview = requireNotNull(model.state.value.preview)
            assertTrue(preview.editable)
            val bytes = "updated ü".toByteArray()
            model.savePreviewText(preview, bytes)
            advanceUntilIdle()
            assertEquals(1, opened.replaceCalls)
            assertTrue(opened.replacedEntry === entry)
            assertEquals("updated ü", opened.replacedText)
            assertTrue(bytes.all { it == 0.toByte() })
            assertEquals(null, model.state.value.preview)
            model.leaveRoute()
        }

    @Test fun largeImageAndPdfUseStreamedBackingWithoutCallingSmallPreview() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            listOf("photo.jpg", "manual.pdf").forEach { name ->
                val opened = TestSession(identity, entries = listOf(fileEntry(name, 9L * 1024 * 1024)))
                opened.previewBlock = { error("Small preview must not be used for $name") }
                opened.downloadBlock = { _, sink, _ ->
                    sink.write(byteArrayOf(1, 2, 3, 4))
                    4L
                }
                val model =
                    newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
                enterAndUnlock(model)
                model.openPreview(
                    model.state.value.entries
                        .single()
                        .id,
                )
                advanceUntilIdle()
                val preview = requireNotNull(model.state.value.preview)
                assertEquals(1, opened.downloadCalls)
                assertEquals(4L, requireNotNull(preview.backing).size)
                assertTrue(preview.bytes.isEmpty())
                model.leaveRoute()
            }
        }

    @Test fun largeStreamedTextRangeSaveKeepsSurroundingBytesAndIssuedEtag() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val prefixSize = 64 * 1024 - 1
            val suffixSize = 9 * 1024 * 1024
            val old = "🗝️".toByteArray(Charsets.UTF_8)
            val replacement = "🔒".toByteArray(Charsets.UTF_8)
            val total = prefixSize.toLong() + old.size + suffixSize
            val entry = fileEntry("notes.txt", total)
            val opened = TestSession(identity, entries = listOf(entry))
            opened.previewBlock = { error("Large text must use the backing") }
            opened.downloadBlock = { _, sink, _ ->
                writeRepeated(sink, 'a'.code.toByte(), prefixSize)
                sink.write(old)
                writeRepeated(sink, 'b'.code.toByte(), suffixSize)
                total
            }
            opened.replaceBlock = { source, size ->
                assertEquals(total - old.size + replacement.size, size)
                assertRepeated(source, 'a'.code.toByte(), prefixSize)
                val edited = ByteArray(replacement.size)
                assertEquals(edited.size, source.read(edited))
                assertArrayEquals(replacement, edited)
                assertRepeated(source, 'b'.code.toByte(), suffixSize)
                assertEquals(-1, source.read())
            }
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            model.openPreview(
                model.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()
            val preview = requireNotNull(model.state.value.preview)
            assertTrue(preview.editable)
            assertEquals(total, requireNotNull(preview.backing).size)
            val page = readEncryptedTextPage(requireNotNull(preview.backing), 0)
            assertEquals(prefixSize, page.length)
            model.savePreviewTextRange(preview, prefixSize.toLong(), old.size.toLong(), replacement)
            advanceUntilIdle()
            assertEquals(1, opened.replaceCalls)
            assertTrue(opened.replacedEntry === entry)
            assertEquals("\"v1\"", opened.replacedEntry?.strongETag)
            assertTrue(replacement.all { it == 0.toByte() })
            assertEquals(null, model.state.value.preview)
            model.leaveRoute()
        }

    @Test fun lockDuringLargePreviewDownloadDeletesUnpublishedCiphertext() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val context = ApplicationProvider.getApplicationContext<Application>()
            val cache = File(context.cacheDir, "encrypted-previews")
            val started = CompletableDeferred<Unit>()
            val unwound = CompletableDeferred<Unit>()
            val opened = TestSession(identity, entries = listOf(fileEntry("large.pdf", 9L * 1024 * 1024)))
            opened.downloadBlock = { _, sink, _ ->
                sink.write(ByteArray(64 * 1024) { 7 })
                started.complete(Unit)
                try {
                    suspendCancellableCoroutine { }
                } finally {
                    unwound.complete(Unit)
                }
            }
            val model = newViewModel(context, TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            model.openPreview(
                model.state.value.entries
                    .single()
                    .id,
            )
            runCurrent()
            started.await()
            assertTrue(cache.listFiles().orEmpty().any { it.isFile })
            model.lock()
            advanceUntilIdle()
            unwound.await()
            assertEquals(null, model.state.value.preview)
            assertTrue(cache.listFiles().isNullOrEmpty())
            model.leaveRoute()
        }

    @Test fun staleAndOfflineTextSaveCannotWriteAndWipesBuffers() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity, entries = listOf(fileEntry("notes.txt")), isOffline = true)
            opened.previewBlock = { "offline".toByteArray() }
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            model.openPreview(
                model.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()
            val preview = requireNotNull(model.state.value.preview)
            assertFalse(preview.editable)
            val offlineBytes = "should not save".toByteArray()
            model.savePreviewText(preview, offlineBytes)
            assertTrue(offlineBytes.all { it == 0.toByte() })
            model.lock()
            val staleBytes = "stale".toByteArray()
            model.savePreviewText(preview, staleBytes)
            assertTrue(staleBytes.all { it == 0.toByte() })
            assertEquals(0, opened.replaceCalls)
            model.leaveRoute()
        }

    @Test fun failedEncryptedTextSaveCannotBlindlyRetryConsumedVersion() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity, entries = listOf(fileEntry("notes.txt")))
            opened.previewBlock = { "original".toByteArray() }
            opened.replaceFailure = java.io.IOException("synthetic uncertain write")
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            model.openPreview(
                model.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()
            val preview = requireNotNull(model.state.value.preview)
            val bytes = "edited".toByteArray()
            model.savePreviewText(preview, bytes)
            advanceUntilIdle()
            assertTrue(bytes.all { it == 0.toByte() })
            assertFalse(requireNotNull(model.state.value.preview).editable)
            val retry = "retry".toByteArray()
            model.savePreviewText(requireNotNull(model.state.value.preview), retry)
            assertTrue(retry.all { it == 0.toByte() })
            assertEquals(1, opened.replaceCalls)
            model.leaveRoute()
        }

    @Test fun cancellationBeforeTextSaveStartsStillWipesOwnedBuffer() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity, entries = listOf(fileEntry("notes.txt")))
            opened.previewBlock = { "original".toByteArray() }
            val model = newViewModel(ApplicationProvider.getApplicationContext(), TestRepository(mutableListOf(opened)))
            enterAndUnlock(model)
            model.openPreview(
                model.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()
            val bytes = "edited".toByteArray()
            model.savePreviewText(requireNotNull(model.state.value.preview), bytes)
            model.lock()
            advanceUntilIdle()
            assertTrue(bytes.all { it == 0.toByte() })
            assertEquals(0, opened.replaceCalls)
            model.leaveRoute()
        }

    @Test fun textEditorRejectsInvalidUtf8AndOversizedBuffers() {
        assertTrue(validEditableText("hello ü".toByteArray()))
        assertFalse(validEditableText(byteArrayOf(0xc3.toByte(), 0x28)))
        assertFalse(validEditableText(ByteArray(MAX_VAULT_EDIT_TEXT_BYTES + 1)))
    }

    private fun writeRepeated(
        sink: OutputStream,
        byte: Byte,
        count: Int,
    ) {
        val block = ByteArray(8192) { byte }
        var remaining = count
        while (remaining > 0) {
            val length = minOf(block.size, remaining)
            sink.write(block, 0, length)
            remaining -= length
        }
        block.fill(0)
    }

    private fun assertRepeated(
        source: InputStream,
        byte: Byte,
        count: Int,
    ) {
        val block = ByteArray(8192)
        var remaining = count
        while (remaining > 0) {
            val requested = minOf(block.size, remaining)
            val read = source.read(block, 0, requested)
            assertTrue("Expected $remaining more bytes", read > 0)
            var mismatch = -1
            for (index in 0 until read) {
                if (block[index] != byte) {
                    mismatch = index
                    break
                }
            }
            assertEquals("Unexpected byte in streamed range", -1, mismatch)
            remaining -= read
        }
        block.fill(0)
    }

    private suspend fun kotlinx.coroutines.test.TestScope.enterAndUnlock(viewModel: VaultViewModel) {
        viewModel.enterRoute(ACCOUNT)
        runCurrent()
        viewModel.selectLocation(
            viewModel.state.value.locations
                .single()
                .id,
        )
        viewModel.unlock("password".toCharArray())
        advanceUntilIdle()
    }

    private fun newViewModel(
        context: Application,
        repository: TestRepository,
    ) = VaultViewModel(
        context,
        repository,
        TestBiometricStore(),
        TestPreferences(),
        ioDispatcher = Dispatchers.Main,
    )

    private class TestRepository(
        private val sessions: MutableList<TestSession>,
        private val availableLocations: List<VaultLocation> = listOf(location),
        private val unlockFailure: Throwable? = null,
    ) : VaultRouteRepository {
        var offlineRemovalCalls = 0

        override suspend fun removeOffline(identity: VaultIdentity) {
            offlineRemovalCalls++
        }

        var onlineCatalogCalls = 0
        var lastUnlockTarget: VaultLocation? = null
        var uploadCalls = 0
        var uploadedText = ""

        override suspend fun locations(accountId: String): List<VaultLocation> {
            onlineCatalogCalls++
            return availableLocations.filter { it.accountId == accountId }
        }

        override suspend fun offlineLocations(accountId: String) =
            availableLocations.map { it.copy(offlineOnly = true) }

        override suspend fun folders(
            accountId: String,
            location: VaultLocation,
            path: String,
        ) = emptyList<VaultFolder>()

        override suspend fun unlock(
            accountId: String,
            target: VaultLocation,
            vaultPath: String,
            password: CharArray,
        ): VaultRouteSession {
            unlockFailure?.let { throw it }
            lastUnlockTarget = target
            return sessions.removeAt(0).also { it.repository = this }
        }

        override suspend fun unlockWithKeyMaterial(
            accountId: String,
            target: VaultLocation,
            vaultPath: String,
            keyMaterial: ByteArray,
        ) = error("Unused")

        fun upload(bytes: ByteArray) {
            uploadCalls++
            uploadedText = bytes.decodeToString()
        }
    }

    private class TestSession(
        override val identity: VaultIdentity,
        var entries: List<VaultFolder> = listOf(fileEntry()),
        override val isOffline: Boolean = false,
        private val encodeBlock: suspend (String) -> String = { it },
    ) : VaultRouteSession {
        lateinit var repository: TestRepository

        var moveCalls = 0
        var copyCalls = 0
        var lastList = ""
        var lastListBeforeCopy: String? = null

        override suspend fun list(path: String): List<VaultFolder> {
            lastList = path
            return if (path.isEmpty()) entries else destinationEntries
        }

        var destinationEntries: List<VaultFolder> = emptyList()
        var copiedName: String? = null

        override suspend fun move(
            entry: VaultFolder,
            destinationPath: String,
            newName: String,
        ): VaultFolder {
            moveCalls++
            copiedName = newName
            return entry
        }

        override suspend fun copy(
            entry: VaultFolder,
            destinationPath: String,
            newName: String,
        ): VaultFolder {
            copyCalls++
            copiedName = newName
            lastListBeforeCopy = lastList
            return entry
        }

        var replaceCalls = 0
        var replacedEntry: VaultFolder? = null
        var replacedText: String? = null
        var replaceFailure: Throwable? = null
        var replaceBlock: ((InputStream, Long) -> Unit)? = null

        override suspend fun replaceText(
            entry: VaultFolder,
            source: InputStream,
            size: Long,
        ): VaultFolder {
            replaceCalls++
            replacedEntry = entry
            val custom = replaceBlock
            if (custom == null) replacedText = source.readBytes().decodeToString() else custom(source, size)
            replaceFailure?.let { throw it }
            return entry
        }

        var previewBlock: suspend () -> ByteArray = { error("Unused") }

        override suspend fun preview(entry: VaultFolder) = previewBlock()

        override suspend fun exportVerifiedKeyMaterial() = ByteArray(80)

        override suspend fun encodeDirectoryPath(plainPath: String) = encodeBlock(plainPath)

        override suspend fun decodeDirectoryPath(encryptedRelativePath: String) = encryptedRelativePath

        override suspend fun upload(
            parentPath: String,
            name: String,
            source: InputStream,
            size: Long,
            mimeType: String?,
        ): VaultFolder {
            repository.upload(source.readBytes())
            return fileEntry(name, size)
        }

        var downloadCalls = 0
        var downloadBlock: (suspend (VaultFolder, OutputStream, Long) -> Long)? = null

        override suspend fun download(
            entry: VaultFolder,
            sink: OutputStream,
            maxPlaintextBytes: Long,
        ): Long {
            downloadCalls++
            return downloadBlock?.invoke(entry, sink, maxPlaintextBytes) ?: 0L
        }

        override fun close() = Unit
    }

    private class TestBiometricStore : VaultBiometricKeyStore {
        override fun hasEnrollment(identity: VaultIdentity) = false

        override fun prepareEnrollment(identity: VaultIdentity): Cipher = error("Unused")

        override fun completeEnrollment(
            identity: VaultIdentity,
            cipher: Cipher,
            keyMaterial: ByteArray,
        ) = Unit

        override fun cancelEnrollment(identity: VaultIdentity) = Unit

        override fun prepareUnlock(identity: VaultIdentity): Cipher = error("Unused")

        override fun completeUnlock(
            identity: VaultIdentity,
            cipher: Cipher,
        ): ByteArray = error("Unused")

        override fun cancelUnlock(identity: VaultIdentity) = Unit

        override fun forget(identity: VaultIdentity) = Unit
    }

    private class TestPreferences : VaultOfferPreferences {
        override fun status(identity: VaultIdentity) = null

        override fun remember(
            identity: VaultIdentity,
            title: String,
            targetKind: VaultPreferenceTargetKind,
        ) = Unit

        override fun decline(
            identity: VaultIdentity,
            title: String,
            targetKind: VaultPreferenceTargetKind,
        ) = Unit

        override fun remove(identity: VaultIdentity) = Unit
    }

    private fun registerUploadProvider(source: File) {
        UploadProvider(source).also {
            it.attachInfo(RuntimeEnvironment.getApplication(), ProviderInfo().apply { authority = AUTHORITY })
            ShadowContentResolver.registerProviderInternal(AUTHORITY, it)
        }
    }

    private class UploadProvider(
        private val file: File,
    ) : ContentProvider() {
        override fun onCreate() = true

        override fun getType(uri: Uri) = "text/plain"

        override fun openFile(
            uri: Uri,
            mode: String,
        ) = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            args: Array<out String>?,
            sort: String?,
        ): Cursor =
            MatrixCursor(
                arrayOf(android.provider.OpenableColumns.DISPLAY_NAME, android.provider.OpenableColumns.SIZE),
            ).apply {
                addRow(arrayOf<Any>("upload.txt", file.length()))
            }

        override fun insert(
            uri: Uri,
            values: ContentValues?,
        ): Uri? = null

        override fun delete(
            uri: Uri,
            selection: String?,
            args: Array<out String>?,
        ) = 0

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            args: Array<out String>?,
        ) = 0
    }

    companion object {
        private const val ACCOUNT = "vault-test-account"
        private const val OTHER_ACCOUNT = "other-test-account"
        private const val AUTHORITY = "vault-upload.test"
        private val identity = VaultIdentity(ACCOUNT, "https://cloud.example", "drive", "root")
        private val location =
            VaultLocation(
                accountId = ACCOUNT,
                title = "Private vault",
                kind = VaultLocationKind.FOLDER_VAULT,
                driveId = identity.driveId,
                remoteVaultId = identity.remoteVaultId,
                sourceRootId = "source",
                canonicalServer = identity.canonicalServer,
                rootWebDavUrl = "https://cloud.example/dav/root",
                vaultPath = "vault",
                isVaultRoot = true,
            )

        private fun fileEntry(
            name: String = "notes.txt",
            size: Long = 5L,
        ) = VaultFolder(
            id = "remote-$name",
            name = name,
            rawName = "opaque-$name",
            path = name,
            encryptedPath = "opaque-$name",
            isFolder = false,
            size = size,
            strongETag = "\"v1\"",
        )
    }
}
