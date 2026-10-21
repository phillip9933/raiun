package eu.opencloud.android.next.ui

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
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

    private fun controller(
        repository: BoundaryDestinationRepository,
        dispatcher: kotlinx.coroutines.CoroutineDispatcher,
    ) = BoundaryDestinationController(
        ApplicationProvider.getApplicationContext<Context>(),
        BoundaryTransferRequest(
            "account",
            false,
            unlocked =
                FakeEndpoint(encrypted = true) to
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
