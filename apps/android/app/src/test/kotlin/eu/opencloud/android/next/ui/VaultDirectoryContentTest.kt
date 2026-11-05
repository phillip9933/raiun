package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultDirectoryContentTest {
    private class Owner : VaultDirectoryOwner {
        var hidden = false
        var current = true
        var clears = 0

        override fun showHidden() = hidden

        override fun isCurrent(
            opened: VaultRouteSession,
            token: Long,
            account: String,
        ) = current

        override fun isRouteCurrent(
            token: Long,
            account: String,
        ) = current

        override fun present(entries: List<VaultFolder>): List<VaultRouteEntry> = emptyList()

        override fun clearPresented() {
            clears++
        }

        override fun reportFailure(
            failure: Exception,
            token: Long,
            account: String,
        ) = Unit
    }

    private class Snapshot(
        private val onPage: () -> Unit = {},
    ) : VaultRouteDirectorySnapshot {
        var closed = false
        override val totalCount = 1L

        override suspend fun page(
            offset: Long,
            limit: Int,
        ): List<VaultFolder> {
            onPage()
            return emptyList()
        }

        override fun close() {
            closed = true
        }
    }

    private class Session(
        private val open: (Boolean) -> Snapshot,
    ) : VaultRouteSession {
        override val identity = VaultViewModelRaceTest.identity

        override suspend fun list(path: String): List<VaultFolder> = emptyList()

        override suspend fun preview(entry: VaultFolder) = ByteArray(0)

        override suspend fun exportVerifiedKeyMaterial() = ByteArray(0)

        override fun close() = Unit

        override suspend fun openDirectory(
            path: String,
            showHidden: Boolean,
            excludedPath: String?,
        ) = open(showHidden)
    }

    @Test fun `visibility change during first page closes stale snapshot and retries`() =
        runTest {
            val owner = Owner()
            val state = MutableStateFlow(VaultRouteState())
            val first = Snapshot { owner.hidden = true }
            val second = Snapshot()
            val seen = mutableListOf<Boolean>()
            val session =
                Session { hidden ->
                    seen += hidden
                    if (hidden) second else first
                }
            val content = VaultDirectoryContent(state, owner)
            val result = content.openFirst(session, "")
            assertEquals(listOf(false, true), seen)
            assertTrue(first.closed)
            assertFalse(second.closed)
            content.adopt(result.snapshot)
            content.close()
            assertTrue(second.closed)
            assertEquals(1, owner.clears)
        }

    @Test fun `cancelled first page closes unadopted snapshot`() =
        runTest {
            val snapshot = Snapshot { throw CancellationException() }
            val content = VaultDirectoryContent(MutableStateFlow(VaultRouteState()), Owner())
            try {
                content.openFirst(Session { snapshot }, "")
                error("Expected cancellation")
            } catch (_: CancellationException) {
                assertTrue(snapshot.closed)
            }
        }
}
