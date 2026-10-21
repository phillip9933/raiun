package eu.opencloud.android.next.feature.shares

import eu.opencloud.android.next.core.database.SharedLocalFile
import eu.opencloud.android.next.core.network.SharedMetadataException
import eu.opencloud.android.next.core.network.SharedMetadataStage
import eu.opencloud.android.next.core.sync.SharedDownloadFile
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class IncomingBrowserControllerTest {
    @Test fun metadataFailureShowsOnlyFixedSupportCodeAlongsideLocalizedError() =
        runTest {
            val controller =
                IncomingBrowserController(
                    this,
                    IncomingBrowserBackend { _, _ -> throw SharedMetadataException(SharedMetadataStage.ITEM_IDENTITY) },
                    StandardTestDispatcher(testScheduler),
                    errorMessage = { "Localized metadata error" },
                )
            controller.load("a")
            advanceUntilIdle()
            assertEquals("Localized metadata error [S04]", controller.state.value.error)
            assertFalse(controller.state.value.loading)
            assertTrue(
                controller.state.value.items
                    .isEmpty(),
            )
        }

    @Test fun uploadPickerResultCannotTargetAnotherAccountOrChangedFolder() =
        runTest {
            val queued = mutableListOf<SharedFolderRequest>()
            val backend =
                object : IncomingBrowserBackend {
                    override suspend fun load(
                        account: String,
                        folder: SharedFolderRequest?,
                    ) = IncomingBrowserPage(
                        emptyList(),
                        uploadDestination =
                            if (account ==
                                "a"
                            ) {
                                root.request
                            } else {
                                null
                            },
                    ) { true }

                    override suspend fun upload(
                        destination: SharedFolderRequest,
                        sourceUri: String,
                    ) {
                        queued.add(destination)
                    }
                }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            advanceUntilIdle()
            controller.upload(child.request, "content://file")
            advanceUntilIdle()
            assertTrue(queued.isEmpty())
            controller.upload(root.request, "content://file")
            advanceUntilIdle()
            assertEquals(listOf(root.request), queued)
            controller.load("b")
            advanceUntilIdle()
            controller.upload(root.request, "content://file")
            advanceUntilIdle()
            assertEquals(1, queued.size)
        }

    @Test fun completedAndRemovedCopiesUpdateWithoutReloadingServerListing() =
        runTest {
            val copies = MutableStateFlow(emptyList<SharedLocalFile>())
            val file =
                IncomingBrowserItem.File(
                    "f",
                    SharedDownloadRequest("a", "share", "scope", SharedDownloadFile("f", "/f", 5, "v1")),
                    null,
                )
            var valid = true
            var loads = 0
            val backend =
                IncomingBrowserBackend { _, _ ->
                    loads++
                    IncomingBrowserPage(listOf(file), copies = copies) { valid }
                }
            val controller = IncomingBrowserController(backgroundScope, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            runCurrent()
            val copy = SharedLocalFile("a", "scope", "f", "/f", 5, "v1", "private", "hash", 1, true)
            copies.value = listOf(copy.copy(accountId = "other"), copy)
            runCurrent()
            assertEquals(
                copy,
                (
                    controller.state.value.items
                        .single() as IncomingBrowserItem.File
                ).localCopy,
            )
            copies.value = emptyList()
            runCurrent()
            assertEquals(
                null,
                (
                    controller.state.value.items
                        .single() as IncomingBrowserItem.File
                ).localCopy,
            )
            assertEquals(1, loads)
            valid = false
            copies.value = listOf(copy)
            runCurrent()
            assertTrue(
                controller.state.value.items
                    .isEmpty(),
            )
            assertNotNull(controller.state.value.error)
        }

    @Test fun shortcutRevalidatesNestedScopeAndUsesFreshFolderName() =
        runTest {
            var requested: SharedFolderRequest? = null
            var valid = true
            val backend =
                IncomingBrowserBackend { _, folder ->
                    requested = folder
                    IncomingBrowserPage(emptyList(), folderName = "Renamed folder") { valid }
                }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            advanceUntilIdle()
            controller.openShortcut(child)
            advanceUntilIdle()
            assertEquals(child.request, requested)
            assertEquals(
                "Renamed folder",
                controller.state.value.trail
                    .single()
                    .name,
            )
            val saved = IncomingBrowserTrail.save(controller.state.value.trail)
            assertEquals(child.request, IncomingBrowserTrail.restore("a", saved).single().request)
            controller.openShortcut(child.copy(request = child.request.copy(account = "b")))
            advanceUntilIdle()
            assertEquals(child.request, requested)
            valid = false
            controller.refresh()
            advanceUntilIdle()
            assertNotNull(controller.state.value.error)
            assertTrue(
                controller.state.value.items
                    .isEmpty(),
            )
            assertTrue(controller.back())
            assertTrue(
                controller.state.value.trail
                    .isEmpty(),
            )
        }

    @Test fun restoredTrailIsRevalidatedAndForeignOrBrokenTrailsAreDiscarded() =
        runTest {
            val trail = listOf(root, child)
            val saved = IncomingBrowserTrail.save(trail)
            assertEquals(trail, IncomingBrowserTrail.restore("a", saved))
            assertTrue(IncomingBrowserTrail.restore("b", saved).isEmpty())
            assertTrue(IncomingBrowserTrail.restore("a", saved.dropLast(1)).isEmpty())
            assertTrue(
                IncomingBrowserTrail.restore("a", saved.toMutableList().apply { this[10] = "/other/child" }).isEmpty(),
            )
            var selected: SharedFolderRequest? = null
            val backend =
                IncomingBrowserBackend { _, folder ->
                    selected = folder
                    IncomingBrowserPage(emptyList()) { true }
                }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a", trail)
            assertTrue(controller.state.value.loading)
            advanceUntilIdle()
            assertEquals(child.request, selected)
            assertEquals(trail, controller.state.value.trail)
        }

    @Test fun copyActionsRejectStaleSelectionsAndRefreshAfterCompletion() =
        runTest {
            val file =
                IncomingBrowserItem.File(
                    "photo",
                    SharedDownloadRequest("a", "share", "scope", SharedDownloadFile("f", "/f", 5, "v1")),
                    "image/jpeg",
                )
            val calls = mutableListOf<SharedCopyAction>()
            val finish = CompletableDeferred<Unit>()
            var loads = 0
            val backend =
                IncomingBrowserBackend { _, _ ->
                    loads++
                    IncomingBrowserPage(listOf(file)) { true }
                }
            val controller =
                IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler)) { _, action ->
                    calls.add(action)
                    finish.await()
                }
            controller.load("a")
            advanceUntilIdle()
            controller.changeCopy(file.copy(name = "stale"), SharedCopyAction.REMOVE)
            runCurrent()
            assertTrue(calls.isEmpty())
            controller.changeCopy(file, SharedCopyAction.KEEP)
            runCurrent()
            assertTrue(controller.state.value.loading)
            controller.changeCopy(file, SharedCopyAction.KEEP)
            finish.complete(Unit)
            advanceUntilIdle()
            assertEquals(listOf(SharedCopyAction.KEEP), calls)
            assertEquals(2, loads)
            assertEquals(listOf(file), controller.state.value.items)
        }

    @Test fun unexpectedFailureIsSanitizedAndRefreshRecovers() =
        runTest {
            var fail = true
            val backend =
                IncomingBrowserBackend { _, _ ->
                    if (fail) error("secret server response")
                    IncomingBrowserPage(emptyList()) { true }
                }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            advanceUntilIdle()
            assertNotNull(controller.state.value.error)
            assertFalse(
                controller.state.value.error
                    .orEmpty()
                    .contains("secret"),
            )
            fail = false
            controller.refresh()
            advanceUntilIdle()
            assertEquals(null, controller.state.value.error)
            assertFalse(controller.state.value.loading)
        }

    private val root = IncomingBrowserItem.Folder("Root", SharedFolderRequest("a", "share", "scope", "root", "/"))
    private val child =
        IncomingBrowserItem.Folder(
            "Child",
            SharedFolderRequest("a", "share", "scope", "child", "/child"),
        )

    @Test fun navigatesOnlyVisibleFoldersAndBackStopsAtCatalog() =
        runTest {
            val backend =
                IncomingBrowserBackend { _, folder ->
                    IncomingBrowserPage(if (folder == null) listOf(root) else listOf(child)) { true }
                }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            advanceUntilIdle()
            controller.open(child)
            assertTrue(
                controller.state.value.trail
                    .isEmpty(),
            )
            controller.open(root)
            assertTrue(
                controller.state.value.items
                    .isEmpty(),
            )
            advanceUntilIdle()
            assertEquals(listOf(root), controller.state.value.trail)
            assertEquals(listOf(child), controller.state.value.items)
            assertTrue(controller.back())
            advanceUntilIdle()
            assertEquals(listOf(root), controller.state.value.items)
            assertFalse(controller.back())
        }

    @Test fun lateCancelledAccountLoadCannotReplaceNewAccount() =
        runTest {
            val delayed = CompletableDeferred<Unit>()
            val backend =
                IncomingBrowserBackend { account, _ ->
                    if (account == "a") withContext(NonCancellable) { delayed.await() }
                    IncomingBrowserPage(if (account == "a") listOf(root) else emptyList()) { true }
                }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            runCurrent()
            controller.load("b")
            runCurrent()
            delayed.complete(Unit)
            advanceUntilIdle()
            assertEquals("b", controller.state.value.account)
            assertTrue(
                controller.state.value.items
                    .isEmpty(),
            )
            assertFalse(controller.state.value.loading)
        }

    @Test fun invalidatedPageAndErrorsNeverKeepPreviouslyVisibleRows() =
        runTest {
            var valid = true
            val backend = IncomingBrowserBackend { _, _ -> IncomingBrowserPage(listOf(root), 2) { valid } }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            advanceUntilIdle()
            assertEquals(2, controller.state.value.unavailable)
            valid = false
            controller.refresh()
            advanceUntilIdle()
            assertTrue(
                controller.state.value.items
                    .isEmpty(),
            )
            assertNotNull(controller.state.value.error)
            assertFalse(controller.state.value.loading)
        }

    @Test fun clearPreventsLateFailureFromReappearing() =
        runTest {
            val delayed = CompletableDeferred<Unit>()
            val backend =
                IncomingBrowserBackend { _, _ ->
                    withContext(NonCancellable) { delayed.await() }
                    error("secret response must not be shown")
                }
            val controller = IncomingBrowserController(this, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            runCurrent()
            controller.clear()
            delayed.complete(Unit)
            advanceUntilIdle()
            assertEquals(IncomingBrowserState(), controller.state.value)
        }
}
