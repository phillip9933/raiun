package eu.opencloud.android.next.feature.shares

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.ShareEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.CreateShareRequest
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.sync.CreatedShare
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SharesControllerTest {
    @Test fun accountSwitchClearsPrivateStateAndCancelsOldObserver() =
        runTest {
            val backend = FakeSharesBackend()
            val controller = SharesController(backgroundScope, backend, StandardTestDispatcher(testScheduler))
            controller.load("a", resource("a", "one"))
            runCurrent()
            backend.rows("a").value = listOf(share("a", "old"))
            runCurrent()
            assertEquals(
                "old",
                controller.state.value.shares
                    .single()
                    .remoteId,
            )
            controller.load("b")
            assertNull(controller.state.value.account)
            assertTrue(
                controller.state.value.shares
                    .isEmpty(),
            )
            assertTrue(
                controller.state.value.resourceShares
                    .isEmpty(),
            )
            runCurrent()
            assertEquals(setOf("b"), backend.observers)
            backend.rows("a").value = listOf(share("a", "late"))
            backend.rows("b").value = listOf(share("b", "new"))
            runCurrent()
            assertEquals(
                "b",
                controller.state.value.account
                    ?.id,
            )
            assertEquals(
                "new",
                controller.state.value.shares
                    .single()
                    .remoteId,
            )
        }

    @Test fun lateResourceResponseCannotReplaceNewFileDetails() =
        runTest {
            val backend = FakeSharesBackend()
            val delayed = CompletableDeferred<List<ShareEntity>>()
            backend.readResource = { item ->
                if (item.remoteId ==
                    "old"
                ) {
                    withContext(NonCancellable) { delayed.await() }
                } else {
                    listOf(share("a", "new"))
                }
            }
            val controller = SharesController(backgroundScope, backend, StandardTestDispatcher(testScheduler))
            controller.load("a", resource("a", "old"))
            runCurrent()
            controller.loadResource(resource("a", "new"))
            runCurrent()
            delayed.complete(listOf(share("a", "old")))
            runCurrent()
            assertEquals(
                "new",
                controller.state.value.resourceShares
                    .single()
                    .remoteId,
            )
            assertFalse(controller.state.value.loading)
            assertNull(controller.state.value.error)
        }

    @Test fun oldCreationCannotPublishIntoNewAccountOrClearItsSavingState() =
        runTest {
            val backend = FakeSharesBackend()
            val creation = CompletableDeferred<CreatedShare>()
            val refresh = CompletableDeferred<Unit>()
            backend.createShare = { _, _ -> withContext(NonCancellable) { creation.await() } }
            val controller = SharesController(backgroundScope, backend, StandardTestDispatcher(testScheduler))
            controller.load("a", resource("a", "old"))
            runCurrent()
            controller.createPublicLink("old link", null, null, 1)
            runCurrent()
            backend.refreshShares = { refresh.await() }
            controller.load("b", resource("b", "new"))
            runCurrent()
            creation.complete(CreatedShare(share("a", "created"), null))
            runCurrent()
            assertTrue(controller.state.value.saving)
            assertTrue(
                controller.state.value.resourceShares
                    .isEmpty(),
            )
            assertNull(controller.state.value.message)
            assertNull(controller.state.value.error)
            refresh.complete(Unit)
            runCurrent()
            assertFalse(controller.state.value.saving)
        }

    @Test fun newerRecipientQueryAndClearingQueryDiscardLateResults() =
        runTest {
            val backend = FakeSharesBackend()
            val old = CompletableDeferred<List<ShareRecipient>>()
            backend.search = { query ->
                if (query == "old") withContext(NonCancellable) { old.await() } else listOf(recipient(query))
            }
            val controller = SharesController(backgroundScope, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            runCurrent()
            controller.searchRecipients("old")
            runCurrent()
            controller.searchRecipients("new")
            runCurrent()
            assertEquals(
                "new",
                controller.state.value.recipients
                    .single()
                    .label,
            )
            controller.searchRecipients("")
            old.complete(listOf(recipient("old")))
            runCurrent()
            assertTrue(
                controller.state.value.recipients
                    .isEmpty(),
            )
            assertNull(controller.state.value.error)
        }

    @Test fun cancellationIsNotAnErrorAndRealFailureIsVisible() =
        runTest {
            val backend = FakeSharesBackend()
            backend.refreshShares = { throw CancellationException("cancelled") }
            val controller = SharesController(backgroundScope, backend, StandardTestDispatcher(testScheduler))
            controller.load("a")
            runCurrent()
            assertNull(controller.state.value.error)
            assertFalse(controller.state.value.saving)
            backend.refreshShares = { throw java.io.IOException("private server detail") }
            controller.refresh()
            runCurrent()
            assertTrue(
                controller.state.value.error
                    .orEmpty()
                    .startsWith("Could not refresh shares:"),
            )
            assertFalse(
                controller.state.value.error
                    .orEmpty()
                    .contains("private server detail"),
            )
            assertFalse(controller.state.value.saving)
        }

    @Test fun successfulCreationIsPublishedAndForeignAccountActionsAreIgnored() =
        runTest {
            val backend = FakeSharesBackend()
            val controller = SharesController(backgroundScope, backend, StandardTestDispatcher(testScheduler))
            controller.load("a", resource("a", "file"))
            runCurrent()
            controller.createRecipientShare(recipient("friend"), 1)
            runCurrent()
            assertEquals(
                "created",
                controller.state.value.resourceShares
                    .single()
                    .remoteId,
            )
            assertEquals("Share created.", controller.state.value.message)
            controller.revoke(share("b", "other"))
            controller.updatePermissions(share("b", "other"), 1)
            controller.loadResource(resource("b", "other"))
            runCurrent()
            assertEquals(0, backend.mutations)
            assertEquals(
                "file",
                controller.state.value.resource
                    ?.remoteId,
            )
        }

    private fun resource(
        account: String,
        id: String,
    ) = ResourceEntity(
        account,
        "drive",
        id,
        null,
        "/$id",
        id,
        ResourceKind.FILE,
        null,
        1,
        "etag",
        0,
        0,
    )

    private fun recipient(name: String) = ShareRecipient(OcsShareType.USER, name, name, null, true)
}

private fun share(
    account: String,
    id: String,
) = ShareEntity(
    account,
    id,
    "file",
    "/file",
    0,
    "friend",
    null,
    null,
    1,
    0,
    null,
    null,
    false,
    false,
)

private class FakeSharesBackend : SharesBackend {
    private val values = mutableMapOf<String, MutableStateFlow<List<ShareEntity>>>()
    val observers = mutableSetOf<String>()
    var mutations = 0
    var readResource: suspend (ResourceEntity) -> List<ShareEntity> = { emptyList() }
    var refreshShares: suspend (String) -> Unit = {}
    var search: suspend (String) -> List<ShareRecipient> = { emptyList() }
    var createShare: suspend (String, CreateShareRequest) -> CreatedShare = { id, _ ->
        CreatedShare(share(id, "created"), null)
    }

    fun rows(id: String) = values.getOrPut(id) { MutableStateFlow(emptyList()) }

    override suspend fun account(id: String) = AccountEntity(id, "https://example.test", id, id, "BASIC", false)

    override fun observe(id: String) =
        flow {
            observers.add(id)
            try {
                rows(id).collect { emit(it) }
            } finally {
                observers.remove(id)
            }
        }

    override suspend fun refresh(id: String) = refreshShares(id)

    override suspend fun resourceShares(resource: ResourceEntity) = readResource(resource)

    override suspend fun recipients(
        id: String,
        query: String,
    ) = search(query)

    override suspend fun create(
        id: String,
        request: CreateShareRequest,
    ) = createShare(id, request)

    override suspend fun update(
        id: String,
        shareId: String,
        permissions: Int,
    ) {
        mutations++
    }

    override suspend fun revoke(
        id: String,
        shareId: String,
    ) {
        mutations++
    }
}
