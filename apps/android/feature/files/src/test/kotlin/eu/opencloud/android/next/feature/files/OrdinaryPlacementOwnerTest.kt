package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.FileOperationNameConflictException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList

class OrdinaryPlacementOwnerTest {
    @Test fun `navigation hides busy UI but retains enqueue ownership and suppresses late conflict`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.owner.place()
                val call = fixture.nextCall()
                fixture.navigate("other-folder")
                assertFalse(fixture.state.value.placementBusy)
                fixture.owner.place()
                assertEquals(1, fixture.calls.size)
                call.fail(FileOperationNameConflictException("first (1).txt"))
                fixture.settle()
                assertNull(fixture.state.value.placementConflict)
                assertNull(fixture.state.value.error)
                assertEquals(listOf(first), fixture.state.value.clipboardItems)
                assertEquals(1, fixture.calls.size)
            }
        }

    @Test fun `account switch preserves new clipboard selection and actions after late success`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.owner.place()
                val call = fixture.nextCall()
                val replacement = first.copy(accountId = "account-b")
                fixture.account = "account-b"
                fixture.state.update {
                    it.copy(
                        clipboard = replacement,
                        clipboardItems = listOf(replacement),
                        selectedIds = setOf("new-selection"),
                        actionResource = replacement,
                    )
                }
                fixture.owner.contextChanged()
                fixture.owner.place()
                assertEquals(1, fixture.calls.size)
                call.succeed()
                fixture.settle()
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(replacement, fixture.state.value.clipboard)
                assertEquals(setOf("new-selection"), fixture.state.value.selectedIds)
                assertEquals(replacement, fixture.state.value.actionResource)
                assertEquals(1, fixture.calls.size)
            }
        }

    @Test fun `batch conflict preserves remainder and keep both never replays admitted sources`() =
        runBlocking {
            Fixture(listOf(first, second, third), moving = true).use { fixture ->
                fixture.owner.place()
                fixture.nextCall().succeed()
                val collision = fixture.nextCall()
                assertEquals(second, collision.source)
                collision.fail(FileOperationNameConflictException("second (1).txt"))
                fixture.settle()
                assertEquals(listOf(second, third), fixture.state.value.clipboardItems)
                assertEquals(
                    "second (1).txt",
                    fixture.state.value.placementConflict
                        ?.suggestedName,
                )

                fixture.owner.keepBothPlacementConflict()
                val retry = fixture.nextCall()
                assertEquals(second, retry.source)
                assertEquals("second (1).txt", retry.name)
                assertEquals(second.name, retry.namingBase)
                assertTrue(retry.moving)
                fixture.owner.keepBothPlacementConflict()
                assertEquals(3, fixture.calls.size)
                retry.fail(FileOperationNameConflictException("second (2).txt"))
                fixture.settle()
                assertEquals(
                    "second (2).txt",
                    fixture.state.value.placementConflict
                        ?.suggestedName,
                )
                assertEquals(listOf(second, third), fixture.state.value.clipboardItems)

                fixture.owner.keepBothPlacementConflict()
                val nextRetry = fixture.nextCall()
                assertEquals("second (2).txt", nextRetry.name)
                assertEquals(second.name, nextRetry.namingBase)
                nextRetry.succeed()
                fixture.settle()
                assertNull(fixture.state.value.placementConflict)
                assertEquals(listOf(third), fixture.state.value.clipboardItems)
                assertEquals(4, fixture.calls.size)

                fixture.owner.place()
                val remainder = fixture.nextCall()
                assertEquals(third, remainder.source)
                remainder.succeed()
                fixture.settle()
                assertNull(fixture.state.value.clipboard)
                assertTrue(
                    fixture.state.value.clipboardItems
                        .isEmpty(),
                )
                assertTrue(
                    fixture.state.value.selectedIds
                        .isEmpty(),
                )
                assertNull(fixture.state.value.actionResource)
                assertEquals(listOf(first, second, second, second, third), fixture.calls.map { it.source })
                assertTrue(fixture.calls.all { it.space == "destination" && it.parent == null && it.moving })
            }
        }

    @Test fun `ordinary failure stops batch without discarding or automatically retrying remainder`() =
        runBlocking {
            Fixture(listOf(first, second, third)).use { fixture ->
                fixture.owner.place()
                fixture.nextCall().succeed()
                fixture.nextCall().fail(IllegalStateException("synthetic private detail"))
                fixture.settle()
                assertEquals(listOf(second, third), fixture.state.value.clipboardItems)
                assertEquals("Safe placement failure", fixture.state.value.error)
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(2, fixture.calls.size)
            }
        }

    @Test fun `scope cancellation cancels pending enqueue without error or batch continuation`() =
        runBlocking {
            Fixture(listOf(first, second)).use { fixture ->
                fixture.owner.place()
                val call = fixture.nextCall()
                val jobs =
                    fixture.scope.coroutineContext[Job]!!
                        .children
                        .toList()
                fixture.scope.cancel()
                withTimeout(5000) { jobs.joinAll() }
                assertTrue(call.cancelled.isCompleted)
                assertNull(fixture.state.value.error)
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(listOf(first, second), fixture.state.value.clipboardItems)
                assertEquals(1, fixture.calls.size)
            }
        }

    @Test fun `cancel placement clears clipboard while accepted enqueue keeps exclusive ownership`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.owner.place()
                val call = fixture.nextCall()
                fixture.owner.cancelPlacement()
                assertNull(fixture.state.value.clipboard)
                assertTrue(
                    fixture.state.value.clipboardItems
                        .isEmpty(),
                )
                assertTrue(fixture.state.value.placementBusy)
                fixture.owner.place()
                call.succeed()
                fixture.settle()
                assertFalse(fixture.state.value.placementBusy)
                assertNull(fixture.state.value.error)
                assertEquals(1, fixture.calls.size)
            }
        }

    @Test fun `late keep both failure cannot publish after destination changes`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.owner.place()
                fixture.nextCall().fail(FileOperationNameConflictException("first (1).txt"))
                fixture.settle()
                fixture.owner.keepBothPlacementConflict()
                val retry = fixture.nextCall()
                fixture.navigate("other-folder")
                fixture.owner.keepBothPlacementConflict()
                retry.fail(IllegalStateException("synthetic private detail"))
                fixture.settle()
                assertNull(fixture.state.value.error)
                assertNull(fixture.state.value.placementConflict)
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(listOf(first), fixture.state.value.clipboardItems)
                assertEquals(2, fixture.calls.size)
            }
        }

    @Test fun `foreign account clipboard and stale conflict are rejected without enqueue`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.account = "account-b"
                fixture.owner.place()
                assertNull(fixture.state.value.clipboard)
                assertTrue(fixture.calls.isEmpty())
                fixture.state.update {
                    it.copy(
                        placementConflict =
                            FileOperationPlacementConflict(
                                first,
                                "destination",
                                null,
                                false,
                                "copy.txt",
                            ),
                    )
                }
                fixture.owner.keepBothPlacementConflict()
                assertNull(fixture.state.value.placementConflict)
                assertTrue(fixture.calls.isEmpty())
            }
        }

    @Test fun `navigation roundtrip rejects late conflict and releases gate for a fresh placement`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.owner.place()
                val old = fixture.nextCall()
                fixture.navigate("other-folder")
                fixture.navigate(null)
                val replacement = second.copy(eTag = "replacement-version")
                fixture.replaceClipboard(listOf(replacement))
                fixture.owner.place()
                assertEquals(1, fixture.calls.size)
                assertFalse(fixture.state.value.placementBusy)
                old.fail(FileOperationNameConflictException("first (1).txt"))
                fixture.settle()
                assertNull(fixture.state.value.placementConflict)
                assertNull(fixture.state.value.error)
                assertEquals(listOf(replacement), fixture.state.value.clipboardItems)
                assertEquals(setOf("replacement-selection"), fixture.state.value.selectedIds)
                assertEquals(replacement, fixture.state.value.actionResource)

                fixture.owner.place()
                val fresh = fixture.nextCall()
                assertEquals(replacement, fresh.source)
                assertTrue(fixture.state.value.placementBusy)
                fresh.succeed()
                fixture.settle()
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(2, fixture.calls.size)
            }
        }

    @Test fun `navigation roundtrip rejects late success and stops remaining batch`() =
        runBlocking {
            Fixture(listOf(first, second), moving = true).use { fixture ->
                fixture.owner.place()
                val old = fixture.nextCall()
                fixture.navigate("other-folder")
                fixture.navigate(null)
                fixture.replaceClipboard(listOf(first.copy(eTag = "replacement-version"), third))
                val replacement = fixture.state.value
                old.succeed()
                fixture.settle()
                assertEquals(replacement, fixture.state.value)
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(1, fixture.calls.size)
            }
        }

    @Test fun `account roundtrip without an intervening Space rejects late failure`() =
        runBlocking {
            Fixture().use { fixture ->
                fixture.owner.place()
                val old = fixture.nextCall()
                // No location notification occurs for B: it never receives a Space.
                fixture.changeAccount("account-b")
                fixture.changeAccount("account-a")
                fixture.replaceClipboard(listOf(second))
                fixture.owner.place()
                assertEquals(1, fixture.calls.size)
                old.fail(IllegalStateException("synthetic private detail"))
                fixture.settle()
                assertNull(fixture.state.value.error)
                assertNull(fixture.state.value.placementConflict)
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(listOf(second), fixture.state.value.clipboardItems)
                assertEquals(setOf("replacement-selection"), fixture.state.value.selectedIds)
                assertEquals(second, fixture.state.value.actionResource)

                fixture.owner.place()
                fixture.nextCall().succeed()
                fixture.settle()
                assertEquals(2, fixture.calls.size)
                assertFalse(fixture.state.value.placementBusy)
            }
        }

    @Test fun `keep both roundtrip retains conflict remainder after late accepted enqueue`() =
        runBlocking {
            Fixture(listOf(first, second, third), moving = true).use { fixture ->
                fixture.owner.place()
                fixture.nextCall().succeed()
                fixture.nextCall().fail(FileOperationNameConflictException("second (1).txt"))
                fixture.settle()
                fixture.owner.keepBothPlacementConflict()
                val retry = fixture.nextCall()
                assertEquals(second.name, retry.namingBase)
                assertEquals("second (1).txt", retry.name)
                fixture.navigate("other-folder")
                fixture.navigate(null)
                fixture.owner.place()
                assertEquals(3, fixture.calls.size)
                retry.succeed()
                fixture.settle()
                assertNull(fixture.state.value.placementConflict)
                assertNull(fixture.state.value.error)
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(listOf(second, third), fixture.state.value.clipboardItems)
                assertEquals(listOf(first, second, second), fixture.calls.map { it.source })
            }
        }

    @Test fun `same account and location no-op refresh preserves active batch and conflict remainder`() =
        runBlocking {
            Fixture(listOf(first, second)).use { fixture ->
                fixture.owner.place()
                val pending = fixture.nextCall()
                fixture.changeAccount("account-a")
                fixture.navigate(null)
                assertTrue(fixture.state.value.placementBusy)
                pending.succeed()
                fixture.nextCall().fail(FileOperationNameConflictException("second (1).txt"))
                fixture.settle()
                assertFalse(fixture.state.value.placementBusy)
                assertEquals(listOf(second), fixture.state.value.clipboardItems)
                assertEquals(
                    second,
                    fixture.state.value.placementConflict
                        ?.source,
                )
                assertEquals(
                    "second (1).txt",
                    fixture.state.value.placementConflict
                        ?.suggestedName,
                )
                assertEquals(2, fixture.calls.size)
            }
        }

    private class Fixture(
        sources: List<ResourceEntity> = listOf(first),
        moving: Boolean = false,
    ) : AutoCloseable {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val state =
            MutableStateFlow(
                FileBrowserUiState(
                    spaceId = "destination",
                    clipboard = sources.first(),
                    clipboardItems = sources,
                    moving = moving,
                    selectedIds = setOf("selection"),
                    actionResource = sources.first(),
                ),
            )

        @Volatile var account = "account-a"
        val calls = CopyOnWriteArrayList<Call>()
        private val pending = Channel<Call>(Channel.UNLIMITED)
        val owner =
            OrdinaryPlacementOwner(
                scope = scope,
                state = state,
                currentAccount = { account },
                reduce = { transform -> state.update(transform) },
                failureMessage = { "Safe placement failure" },
                enqueue = { source, space, parent, name, move, namingBase ->
                    val call = Call(source, space, parent, name, move, namingBase)
                    calls.add(call)
                    pending.send(call)
                    try {
                        call.result.await()
                    } catch (cancelled: CancellationException) {
                        call.cancelled.complete(Unit)
                        throw cancelled
                    }
                },
            )

        suspend fun nextCall(): Call = withTimeout(5000) { pending.receive() }

        suspend fun settle() =
            withTimeout(5000) {
                scope.coroutineContext[Job]!!
                    .children
                    .toList()
                    .joinAll()
            }

        fun navigate(parent: String?) {
            if (state.value.currentFolderId == parent) return
            owner.contextChanged()
            state.update { it.copy(currentFolderId = parent) }
        }

        fun changeAccount(next: String) {
            if (account == next) return
            owner.contextChanged()
            account = next
        }

        fun replaceClipboard(sources: List<ResourceEntity>) {
            state.update {
                it.copy(
                    clipboard = sources.first(),
                    clipboardItems = sources,
                    selectedIds = setOf("replacement-selection"),
                    actionResource = sources.first(),
                )
            }
        }

        override fun close() = scope.cancel()
    }

    private class Call(
        val source: ResourceEntity,
        val space: String,
        val parent: String?,
        val name: String,
        val moving: Boolean,
        val namingBase: String,
    ) {
        val result = CompletableDeferred<Unit>()
        val cancelled = CompletableDeferred<Unit>()

        fun succeed() = result.complete(Unit)

        fun fail(error: Exception) = result.completeExceptionally(error)
    }

    private companion object {
        val first = resource("first")
        val second = resource("second")
        val third = resource("third")

        fun resource(id: String) =
            ResourceEntity(
                "account-a",
                "source",
                id,
                null,
                "/$id.txt",
                "$id.txt",
                ResourceKind.FILE,
                "text/plain",
                1,
                "tag",
                1,
                1,
            )
    }
}
