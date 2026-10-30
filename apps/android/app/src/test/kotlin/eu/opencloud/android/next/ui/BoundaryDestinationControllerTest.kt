package eu.opencloud.android.next.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.sync.BoundaryDestinationFolder
import eu.opencloud.android.next.core.sync.BoundaryDestinationSnapshot
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry
import eu.opencloud.android.next.core.sync.BoundaryNameIndex
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.InputStream
import java.io.OutputStream
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class BoundaryDestinationControllerTest {
    @Test fun `late unlocked destination is closed when dialog has left`() =
        runTest {
            var pending: Continuation<BoundaryUnlockedDestination>? = null
            var released = 0
            val repository = FakeRepository(unlockBlock = { suspendCoroutine { pending = it } })
            val dispatcher = StandardTestDispatcher(testScheduler)
            val controller = controller(repository, dispatcher)
            advanceUntilIdle()
            controller.select(encrypted)
            val password = "synthetic password".toCharArray()
            controller.unlock(password)
            runCurrent()
            controller.close()
            requireNotNull(pending).resume(BoundaryUnlockedDestination(FakeEndpoint()) { released++ })
            advanceUntilIdle()

            assertEquals(1, released)
            assertTrue(password.all { it == '\u0000' })
            assertNull(controller.state.value.location)
        }

    @Test fun `late ordinary destination cannot replace a newer selection`() =
        runTest {
            var pending: Continuation<BoundaryEndpoint>? = null
            val repository =
                FakeRepository(ordinaryBlock = { location ->
                    if (location.driveId == first.driveId) suspendCoroutine { pending = it } else FakeEndpoint()
                })
            val dispatcher = StandardTestDispatcher(testScheduler)
            val controller = controller(repository, dispatcher)
            try {
                advanceUntilIdle()
                controller.select(first)
                runCurrent()
                controller.select(second)
                advanceUntilIdle()
                requireNotNull(pending).resume(FakeEndpoint())
                advanceUntilIdle()

                assertEquals(second, controller.state.value.location)
                assertEquals(false, controller.state.value.loading)
            } finally {
                controller.close()
            }
        }

    @Test fun `changing destination discards a late unlock and its password`() =
        runTest {
            var pending: Continuation<BoundaryUnlockedDestination>? = null
            var released = 0
            val repository = FakeRepository(unlockBlock = { suspendCoroutine { pending = it } })
            val dispatcher = StandardTestDispatcher(testScheduler)
            val controller = controller(repository, dispatcher)
            try {
                advanceUntilIdle()
                controller.select(encrypted)
                val password = "synthetic password".toCharArray()
                controller.unlock(password)
                runCurrent()
                controller.select(second)
                advanceUntilIdle()
                requireNotNull(pending).resume(BoundaryUnlockedDestination(FakeEndpoint()) { released++ })
                advanceUntilIdle()

                assertEquals(second, controller.state.value.location)
                assertTrue(controller.state.value.plaintextWarning)
                assertEquals(1, released)
                assertTrue(password.all { it == '\u0000' })
            } finally {
                controller.close()
            }
        }

    @Test fun `conflict and cancel close reservations while keep both recaptures before preflight`() =
        runBlocking {
            val remoteNames = mutableSetOf("private.txt")
            var captures = 0
            var closes = 0
            var writes = 0
            var writtenName: String? = null
            val source =
                object : BoundaryEndpoint by FakeEndpoint(encrypted = true) {
                    override val identity = "source"

                    override suspend fun requireUnchanged(entry: BoundaryEntry) {
                        assertEquals(captures, closes)
                    }

                    override suspend fun read(
                        entry: BoundaryEntry,
                        sink: OutputStream,
                    ) {
                        sink.write(1)
                    }
                }
            val destination =
                object : BoundaryEndpoint by FakeEndpoint() {
                    override val identity = "destination"

                    override suspend fun openNameIndex(
                        context: Context,
                        path: String,
                    ): BoundaryNameIndex {
                        captures++
                        return TrackingNames(remoteNames) { closes++ }
                    }

                    override suspend fun write(
                        parent: String,
                        name: String,
                        source: InputStream,
                        size: Long,
                        mimeType: String?,
                    ): BoundaryEntry {
                        assertEquals(captures, closes)
                        assertEquals(listOf(1.toByte()), source.readBytes().toList())
                        writes++
                        writtenName = name
                        return BoundaryEntry("copy", name, name, false, 1, "\"1\"")
                    }

                    override suspend fun read(
                        entry: BoundaryEntry,
                        sink: OutputStream,
                    ) {
                        sink.write(1)
                    }
                }
            val controller = controller(FakeRepository(ordinaryBlock = { destination }), Dispatchers.Unconfined, source)
            try {
                controller.select(first)
                controller.transfer()
                assertEquals(
                    "private (1).txt",
                    controller.state.value.conflict
                        ?.proposedName,
                )
                assertEquals(1, captures)
                assertEquals(1, closes)
                assertEquals(0, writes)
                controller.cancelConflict()
                withTimeout(5_000) { controller.state.first { !it.loading } }
                assertNull(controller.state.value.conflict)
                assertEquals(0, writes)
                remoteNames += "private (1).txt"
                controller.keepBoth()
                withTimeout(5_000) { controller.state.first { it.complete || it.error != null } }
                assertTrue(controller.state.value.complete)
                assertEquals(2, captures)
                assertEquals(2, closes)
                assertEquals(1, writes)
                assertEquals("private (2).txt", writtenName)
            } finally {
                controller.close()
            }
        }

    @Test fun `a late name index is closed when the modal is cancelled before planning`() =
        runBlocking {
            var pending: Continuation<BoundaryNameIndex>? = null
            var closes = 0
            val destination =
                object : BoundaryEndpoint by FakeEndpoint() {
                    override val identity = "destination"

                    override suspend fun openNameIndex(
                        context: Context,
                        path: String,
                    ): BoundaryNameIndex = suspendCoroutine { pending = it }
                }
            val controller = controller(FakeRepository(ordinaryBlock = { destination }), Dispatchers.Unconfined)
            controller.select(first)
            controller.transfer()
            val produced = requireNotNull(pending)
            controller.close()
            produced.resume(TrackingNames(emptySet()) { closes++ })
            kotlinx.coroutines.yield()
            assertEquals(1, closes)
            assertTrue(!controller.state.value.complete)
            assertNull(controller.state.value.conflict)
        }

    private class TrackingNames(
        existing: Set<String>,
        private val onClose: () -> Unit,
    ) : BoundaryNameIndex {
        private val names = existing.toMutableSet()
        private var closed = false

        override suspend fun reserve(name: String): Boolean {
            check(!closed)
            return names.add(name)
        }

        override fun close() {
            if (!closed) {
                closed = true
                onClose()
            }
        }
    }

    private fun controller(
        repository: BoundaryDestinationRepository,
        dispatcher: kotlinx.coroutines.CoroutineDispatcher,
        source: BoundaryEndpoint = FakeEndpoint(encrypted = true),
    ) = BoundaryDestinationController(
        ApplicationProvider.getApplicationContext<Context>(),
        BoundaryTransferRequest(
            "account",
            false,
            unlocked =
                source to
                    BoundaryEntry("source", "private.txt", "private.txt", false, 1, "\"1\""),
        ),
        repository,
        dispatcher,
        dispatcher,
    )

    private class FakeRepository(
        private val ordinaryBlock: suspend (VaultLocation) -> BoundaryEndpoint = { FakeEndpoint() },
        private val unlockBlock: suspend () -> BoundaryUnlockedDestination = { error("Unexpected unlock") },
    ) : BoundaryDestinationRepository {
        override suspend fun locations(accountId: String) = listOf(first, second, encrypted)

        override suspend fun ordinaryEndpoint(
            accountId: String,
            location: VaultLocation,
        ) = ordinaryBlock(location)

        override suspend fun folders(
            accountId: String,
            location: VaultLocation,
            path: String,
        ) = emptyList<VaultFolder>()

        override suspend fun unlock(
            accountId: String,
            location: VaultLocation,
            password: CharArray,
        ) = unlockBlock()
    }

    private class FakeEndpoint(
        override val encrypted: Boolean = false,
    ) : BoundaryEndpoint {
        override val identity = "synthetic-endpoint"

        override suspend fun openDestinationFolders(
            context: Context,
            path: String,
        ): BoundaryDestinationSnapshot =
            object : BoundaryDestinationSnapshot {
                override val totalCount = 0L

                override suspend fun page(
                    offset: Long,
                    limit: Int,
                ) = emptyList<BoundaryDestinationFolder>()

                override fun close() = Unit
            }

        override suspend fun list(path: String) = emptyList<BoundaryEntry>()

        override suspend fun requireUnchanged(entry: BoundaryEntry) = Unit

        override suspend fun read(
            entry: BoundaryEntry,
            sink: OutputStream,
        ): Unit = error("Unexpected read")

        override suspend fun write(
            parent: String,
            name: String,
            source: InputStream,
            size: Long,
            mimeType: String?,
        ): BoundaryEntry = error("Unexpected write")

        override suspend fun createDirectory(
            parent: String,
            name: String,
        ): BoundaryEntry = error("Unexpected directory creation")

        override suspend fun delete(entry: BoundaryEntry): Unit = error("Unexpected delete")
    }

    private companion object {
        val first = location("first")
        val second = location("second")
        val encrypted = location("encrypted").copy(kind = VaultLocationKind.SPACE_VAULT, isVaultRoot = true)

        fun location(id: String) =
            VaultLocation(
                accountId = "account",
                title = id,
                kind = VaultLocationKind.SPACE,
                driveId = id,
                remoteVaultId = id,
                sourceRootId = id,
                canonicalServer = "https://example.test",
                rootWebDavUrl = "https://example.test/dav/$id",
                vaultPath = "",
                isVaultRoot = false,
            )
    }
}
