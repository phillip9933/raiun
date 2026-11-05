package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.DirectoryOverlay
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceDirectoryPage
import eu.opencloud.android.next.core.database.ResourceDirectoryPaging
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.update
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
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BackupDestinationPickerOwnerTest {
    @Test fun `late ordinary page cannot publish after account roundtrip and reset`() = stalePage(accountChange = true)

    @Test fun `late ordinary page cannot publish after navigation`() = stalePage(accountChange = false)

    private fun stalePage(accountChange: Boolean) {
        val firstStarted = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val secondStarted = CountDownLatch(1)
        val releaseSecond = CountDownLatch(1)
        val calls = AtomicInteger()
        val reads =
            object : TestReads() {
                override suspend fun load(
                    account: String,
                    space: String,
                    parent: String?,
                    offset: Int,
                    overlays: List<DirectoryOverlay>,
                ): ResourceDirectoryPage {
                    val first = calls.incrementAndGet() == 1
                    if (first) firstStarted.countDown() else secondStarted.countDown()
                    withContext(NonCancellable) {
                        if (first) releaseFirst.await() else releaseSecond.await()
                    }
                    return ResourceDirectoryPage(0, if (first) 111 else 222, emptyList())
                }
            }
        val fixture = Fixture(reads)
        try {
            fixture.onMain { fixture.owner.start() }
            fixture.onMain { fixture.owner.openBackupPickerSpace(space("account-a", "space-a")) }
            assertTrue(firstStarted.await(5, TimeUnit.SECONDS))
            if (accountChange) {
                fixture.onMain {
                    fixture.account = "account-b"
                    fixture.owner.resetForAccount()
                    fixture.account = "account-a"
                    fixture.owner.resetForAccount()
                }
            }
            fixture.onMain { fixture.owner.openBackupPickerSpace(space(fixture.account, "space-b")) }
            releaseFirst.countDown()
            assertTrue(secondStarted.await(5, TimeUnit.SECONDS))
            assertEquals(
                "space-b",
                fixture.state.value.backupPickerDestination
                    ?.spaceId,
            )
            assertEquals(null, fixture.state.value.backupPickerPage)
            assertFalse(fixture.state.value.backupPickerCanSelect)
        } finally {
            releaseFirst.countDown()
            releaseSecond.countDown()
            fixture.close()
        }
    }

    @Test fun `same root reopen emits a fresh request and later invalidations load`() = reopenSameRoot(false)

    @Test fun `account roundtrip to same root emits a fresh request and later invalidations load`() =
        reopenSameRoot(
            true,
        )

    private fun reopenSameRoot(accountRoundtrip: Boolean) {
        val invalidations = MutableStateFlow(0)
        val calls = AtomicInteger()
        val reads =
            object : TestReads() {
                override fun invalidations(
                    account: String,
                    space: String,
                    parent: String?,
                ) = invalidations

                override suspend fun load(
                    account: String,
                    space: String,
                    parent: String?,
                    offset: Int,
                    overlays: List<DirectoryOverlay>,
                ): ResourceDirectoryPage = ResourceDirectoryPage(0, calls.incrementAndGet(), emptyList())
            }
        val fixture = Fixture(reads)
        try {
            fixture.onMain {
                fixture.owner.start()
                fixture.owner.openBackupPickerSpace(space("account-a", "space-a"))
            }
            fixture.awaitTotal(1)
            fixture.onMain {
                if (accountRoundtrip) {
                    fixture.account = "account-b"
                    fixture.owner.resetForAccount()
                    fixture.account = "account-a"
                    fixture.owner.resetForAccount()
                }
                // Both writes occur before the Main collector can observe the intermediate null.
                fixture.owner.openBackupPickerSpace(space("account-a", "space-a"))
            }
            fixture.awaitTotal(2)
            invalidations.value++
            fixture.awaitTotal(3)
            assertTrue(fixture.state.value.backupPickerCanSelect)
        } finally {
            fixture.close()
        }
    }

    @Test fun `scope cancellation cancels pending ordinary page`() {
        val started = CountDownLatch(1)
        val cancelled = CountDownLatch(1)
        val reads =
            object : TestReads() {
                override suspend fun load(
                    account: String,
                    space: String,
                    parent: String?,
                    offset: Int,
                    overlays: List<DirectoryOverlay>,
                ): ResourceDirectoryPage =
                    try {
                        started.countDown()
                        awaitCancellation()
                    } finally {
                        cancelled.countDown()
                    }
            }
        val fixture = Fixture(reads)
        fixture.onMain { fixture.owner.start() }
        fixture.onMain { fixture.owner.openBackupPickerSpace(space("account-a", "space-a")) }
        assertTrue(started.await(5, TimeUnit.SECONDS))
        fixture.scope.cancel()
        assertTrue(cancelled.await(5, TimeUnit.SECONDS))
        assertEquals(null, fixture.state.value.backupPickerPage)
        assertFalse(fixture.state.value.backupPickerCanSelect)
        fixture.close()
    }

    @Test fun `account reset clears complete picker presentation and revokes selection without another Space`() {
        val fixture = Fixture(TestReads())
        try {
            fixture.onMain {
                fixture.owner.openBackupPickerSpace(space("account-a", "space-a"))
                fixture.state.update {
                    it.copy(
                        backupPickerTrail = listOf(BackupFolderCrumb("child", "Child", "/Child")),
                        backupPickerResources =
                            listOf(
                                ResourceEntity(
                                    "account-a",
                                    "space-a",
                                    "child",
                                    null,
                                    "/Child",
                                    "Child",
                                    ResourceKind.FOLDER,
                                    null,
                                    0,
                                    null,
                                    0,
                                    0,
                                ),
                            ),
                        backupPickerSharedRoots = listOf(BackupSharedRoot("Shared", "share", "scope", "root")),
                        backupPickerSharedNames = mapOf("share" to "Shared"),
                        backupPickerSharedFolders = listOf(BackupSharedFolder("child", "Child", "/Child")),
                        backupPickerPage = BackupPickerPageState(128, 300, 128),
                        backupPickerLoading = true,
                        backupPickerCanSelect = true,
                        backupPickerError = "Previous account picker error",
                        layout = BrowserLayout.TILES,
                    )
                }
                assertTrue(fixture.state.value.backupPickerCanSelect)
                fixture.account = "account-b"
                fixture.owner.resetForAccount()
                // No B Space or replacement picker request arrives to clear these fields later.
                val reset = fixture.state.value
                assertNull(reset.backupPickerDestination)
                assertNull(reset.backupPickerPage)
                assertNull(reset.backupPickerError)
                assertFalse(reset.backupPickerLoading)
                assertFalse(reset.backupPickerCanSelect)
                assertTrue(reset.backupPickerTrail.isEmpty())
                assertTrue(reset.backupPickerResources.isEmpty())
                assertTrue(reset.backupPickerSharedRoots.isEmpty())
                assertTrue(reset.backupPickerSharedNames.isEmpty())
                assertTrue(reset.backupPickerSharedFolders.isEmpty())
                assertEquals(BrowserLayout.TILES, reset.layout)
                fixture.owner.pageBackupPicker(previous = false)
                assertEquals(reset, fixture.state.value)
            }
        } finally {
            fixture.close()
        }
    }

    private open class TestReads : BackupPickerOrdinaryReads {
        override fun invalidations(
            account: String,
            space: String,
            parent: String?,
        ) = flowOf(1)

        override suspend fun overlays(
            account: String,
            space: String,
            path: String,
        ) = emptyList<DirectoryOverlay>()

        override suspend fun load(
            account: String,
            space: String,
            parent: String?,
            offset: Int,
            overlays: List<DirectoryOverlay>,
        ) = ResourceDirectoryPage(0, 0, emptyList())
    }

    private class Fixture(
        reads: BackupPickerOrdinaryReads,
    ) {
        private val main = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        fun onMain(action: () -> Unit) = runBlocking { withContext(main) { action() } }

        fun awaitTotal(expected: Int) =
            runBlocking {
                withTimeout(5000) {
                    while (state.value.backupPickerPage?.total != expected) delay(10)
                }
            }

        fun close() {
            scope.cancel()
            main.close()
        }

        val state = MutableStateFlow(FileBrowserUiState())

        @Volatile var account = "account-a"
        private val application = RuntimeEnvironment.getApplication()
        private val database = FileBrowserDatabase.create(application)
        val owner =
            BackupDestinationPickerOwner(
                application = application,
                scope = scope,
                directoryPaging = ResourceDirectoryPaging(database),
                store = FileBrowserStore(database),
                refreshFolder = { _, _, _ -> UUID.randomUUID() },
                createFolder = { _, _, _, _ -> },
                state = state,
                currentAccount = { account },
                reduce = { transform -> state.update(transform) },
                observeDiscovery = {},
                ordinaryReads = reads,
                mainDispatcher = main,
            )
    }

    private fun space(
        account: String,
        id: String,
    ) = SpaceEntity(account, id, id, "personal", null, null, "root", null, null, null)
}
