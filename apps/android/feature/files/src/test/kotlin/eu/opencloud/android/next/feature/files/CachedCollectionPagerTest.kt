package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.DirectorySort
import eu.opencloud.android.next.core.database.ResourceCollectionOptions
import eu.opencloud.android.next.core.database.ResourceCollectionPage
import eu.opencloud.android.next.core.database.ResourceCollectionRoot
import eu.opencloud.android.next.core.database.ResourceDirectoryItem
import eu.opencloud.android.next.core.database.ResourceDirectoryPage
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.CoroutineContext

class CachedCollectionPagerTest {
    private val dispatcher = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val events = MutableSharedFlow<Int>(replay = 1).apply { tryEmit(0) }

    @After fun close() {
        scope.cancel()
        dispatcher.close()
    }

    @Test fun `page failure retains verified rows and totals and retry replaces without appending`() =
        runBlocking(dispatcher) {
            var fail = false
            val pager =
                pager({ events }, { request ->
                    if (fail) error("synthetic disk error")
                    result("row-${request.options.offset}", request.options.offset)
                })
            pager.account("a")
            await(pager) { it.result?.page?.offset == 0 }
            fail = true
            pager.page(false)
            val failed = await(pager) { it.error != null }
            assertTrue(pager.isCurrent(requireNotNull(failed.request)))
            assertEquals(0, failed.result!!.page.offset)
            assertEquals(300, failed.result.page.total)
            fail = false
            // Retry uses the previous verified page, even though the failed request has a later revision.
            pager.page(false)
            val retry = await(pager) { it.result?.page?.offset == 128 && it.error == null }
            assertEquals(
                listOf("row-128"),
                retry.result!!
                    .page.entries
                    .map { it.resource?.remoteId },
            )
            events.emit(1)
            val refreshed = await(pager) { it.result?.page?.offset == 128 }
            assertEquals(
                1,
                refreshed.result!!
                    .page.entries.size,
            )
        }

    @Test fun `account round trip clears the old window immediately and revision rejects late uncancellable results`() =
        runBlocking(dispatcher) {
            val started = CompletableDeferred<Unit>()
            val release = CompletableDeferred<Unit>()
            var calls = 0
            val pager =
                pager({ events }, { request ->
                    if (request.account == "a" && calls++ == 0) {
                        started.complete(Unit)
                        withContext(NonCancellable) { release.await() }
                        result("stale")
                    } else {
                        result("fresh-${request.account}")
                    }
                })
            pager.account("a")
            withTimeout(10_000) { started.await() }
            pager.account("b")
            assertNull(pager.state.value.result)
            pager.account("a")
            assertNull(pager.state.value.result)
            release.complete(Unit)
            val fresh = await(pager) { it.result != null }
            assertEquals(
                "fresh-a",
                fresh.result!!
                    .page.entries
                    .single()
                    .resource
                    ?.remoteId,
            )
            assertEquals("a", fresh.request?.account)
        }

    @Test fun `outer publication can reject cached request after account roundtrip and options change`() =
        runBlocking(dispatcher) {
            val pager = pager({ events }, { request -> result(request.account) })
            pager.account("a")
            val old = requireNotNull(await(pager) { it.result != null }.request)
            assertTrue(pager.isCurrent(old))
            pager.account("b")
            pager.account("a")
            assertFalse(pager.isCurrent(old))
            val returned = requireNotNull(pager.state.value.request)
            assertEquals(old.account, returned.account)
            assertTrue(old.accountRevision != returned.accountRevision)
            pager.options(ResourceCollectionOptions(query = "new query"))
            assertFalse(pager.isCurrent(returned))
        }

    @Test fun `display change resets offset and removes rows from the old filter before new response`() =
        runBlocking(dispatcher) {
            val next = CompletableDeferred<Unit>()
            val pager =
                pager({ events }, { request ->
                    if (request.options.query.isNotEmpty()) next.await()
                    result(request.options.query.ifEmpty { "unfiltered" }, request.options.offset)
                })
            pager.account("a")
            await(pager) { it.result != null }
            pager.page(false)
            await(pager) { it.result?.page?.offset == 128 }
            pager.options(ResourceCollectionOptions(query = "literal_%"))
            assertNull(pager.state.value.result)
            assertEquals(
                0,
                pager.state.value.request
                    ?.options
                    ?.offset,
            )
            next.complete(Unit)
            assertEquals(
                "literal_%",
                await(pager) { it.result != null }
                    .result!!
                    .page.entries
                    .single()
                    .resource
                    ?.name,
            )
        }

    @Test fun `cancellation is not a cache failure and later invalidation can still refresh`() =
        runBlocking(dispatcher) {
            var cancelled = true
            val attempted = Channel<Unit>(Channel.UNLIMITED)
            val pager =
                pager({ events }, {
                    attempted.send(Unit)
                    if (cancelled) throw CancellationException("synthetic cancellation")
                    result("recovered")
                })
            pager.account("a")
            withTimeout(10_000) { attempted.receive() }
            assertNull(pager.state.value.error)
            assertNull(pager.state.value.result)
            cancelled = false
            events.emit(1)
            assertNotNull(await(pager) { it.result != null }.result)
        }

    @Test fun `page sort and search reuse byte totals and database roots and account changes invalidate them`() =
        runBlocking(dispatcher) {
            val byteCalls = AtomicInteger()
            val subscriptions = AtomicInteger()
            val pager =
                pager(
                    {
                        subscriptions.incrementAndGet()
                        events
                    },
                    { result(it.options.query.ifEmpty { "row" }, it.options.offset) },
                    { byteCalls.incrementAndGet().toLong() * 10 },
                )
            pager.account("a")
            await(pager) { it.bytes == 10L }
            pager.page(false)
            await(pager) { it.result?.page?.offset == 128 }
            assertEquals(1, byteCalls.get())
            pager.options(ResourceCollectionOptions(sort = DirectorySort.Size))
            await(pager) { it.result != null && it.request?.options?.sort == DirectorySort.Size }
            assertEquals(1, byteCalls.get())
            pager.options(ResourceCollectionOptions(query = "literal_%"))
            await(pager) { it.result != null && it.request?.options?.query == "literal_%" }
            assertEquals(1, byteCalls.get())
            assertEquals(1, subscriptions.get())
            events.emit(0) // A same-count metadata change must still increment the database event revision.
            await(pager) { it.bytes == 20L }
            assertEquals(2, byteCalls.get())
            pager.roots(listOf(ResourceCollectionRoot("space", "vault", "/vault")))
            await(pager) { it.bytes == 30L }
            assertEquals(1, subscriptions.get())
            pager.account("b")
            await(pager) { it.result != null && it.request?.account == "b" }
            assertEquals(4, byteCalls.get())
            assertEquals(2, subscriptions.get())
        }

    @Test fun `failed byte verification is retried and only the verified result is reused`() =
        runBlocking(dispatcher) {
            val attempts = AtomicInteger()
            val pager =
                pager({ events }, { result("row", it.options.offset) }, {
                    if (attempts.incrementAndGet() == 1) error("synthetic file validation failure")
                    42L
                })
            pager.account("a")
            await(pager) { it.error != null }
            assertNull(pager.state.value.result)
            events.emit(1)
            await(pager) { it.bytes == 42L && it.error == null }
            pager.page(false)
            await(pager) { it.result?.page?.offset == 128 }
            assertEquals(2, attempts.get())
        }

    @Test fun `queued IO result cannot overwrite account reset or its accepted revision`() =
        runBlocking(dispatcher) {
            val admission = QueuedAdmissionDispatcher()
            val loaded = Channel<String>(Channel.UNLIMITED)
            val byteAccounts = java.util.concurrent.CopyOnWriteArrayList<String>()
            val pager =
                CachedCollectionPager(
                    scope,
                    { events },
                    { request ->
                        loaded.send(request.account)
                        result(request.account)
                    },
                    { request ->
                        byteAccounts += request.account
                        if (request.account == "a") 17L else 29L
                    },
                    admission,
                )
            val old = pager.account("a")
            assertEquals("a", withTimeout(10_000) { loaded.receive() })
            admission.next().run() // Read the byte memo on Main.
            val oldPublication = admission.next() // IO verification completed; admission has not run.
            val accepted = pager.account("b")
            assertEquals(accepted, pager.state.value.request)
            oldPublication.run()
            assertEquals(accepted, pager.state.value.request)
            assertNull(pager.state.value.result)
            assertEquals("b", withTimeout(10_000) { loaded.receive() })
            admission.next().run() // B must not reuse an unadmitted A byte memo.
            admission.next().run()
            val published = await(pager) { it.result != null }
            assertEquals(accepted, published.request)
            assertEquals(29L, published.bytes)
            assertEquals(listOf("a", "b"), byteAccounts)
            assertFalse(pager.isCurrent(old))
        }

    private class QueuedAdmissionDispatcher : CoroutineDispatcher() {
        private val tasks = Channel<Runnable>(Channel.UNLIMITED)

        override fun dispatch(
            context: CoroutineContext,
            block: Runnable,
        ) {
            tasks.trySend(block).getOrThrow()
        }

        suspend fun next(): Runnable = withTimeout(10_000) { tasks.receive() }
    }

    private fun pager(
        invalidations: (String) -> Flow<Int>,
        load: suspend (CachedCollectionRequest) -> ResourceCollectionPage,
        bytes: suspend (CachedCollectionRequest) -> Long = { 0 },
    ) = CachedCollectionPager(scope, invalidations, load, bytes, dispatcher)

    private suspend fun await(
        pager: CachedCollectionPager,
        predicate: (CachedCollectionState) -> Boolean,
    ) = withTimeout(10_000) { pager.state.first(predicate) }

    private fun result(
        name: String,
        offset: Int = 0,
    ): ResourceCollectionPage {
        val row = ResourceEntity("a", "space", name, null, name, name, ResourceKind.FILE, "text/plain", 1, "tag", 1, 1)
        return ResourceCollectionPage(
            ResourceDirectoryPage(offset, 300, listOf(ResourceDirectoryItem(resource = row))),
            emptyList(),
        )
    }
}
