package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProviderWriteBarrierTest {
    private val edit =
        DocumentEdit("upload", "a", "s", "r", "/backup", "backup", null, "\"v1\"", DocumentEditState.SUBMITTED)

    @Test fun `subsequent operation waits for upload settlement`() =
        runTest {
            var pending = true
            var reconciliations = 0
            awaitProviderWrites({ if (pending) listOf(edit) else emptyList() }, { "SUCCEEDED" }, { true }) {
                reconciliations++
                pending = false
            }
            assertEquals(1, reconciliations)
        }

    @Test fun `failed cancelled missing or conflicted upload blocks subsequent mutation`() {
        listOf("FAILED", "CANCELLED", "CONFLICT", null).forEach { state ->
            assertThrows(IllegalStateException::class.java) {
                runTest { awaitProviderWrites({ listOf(edit) }, { state }, { true }) {} }
            }
        }
    }

    @Test fun `recovery draft and revoked access block subsequent mutation`() {
        assertThrows(IllegalStateException::class.java) {
            runTest {
                awaitProviderWrites(
                    { listOf(edit.copy(state = DocumentEditState.REVIEW)) },
                    { null },
                    { true },
                ) {}
            }
        }
        assertThrows(IllegalStateException::class.java) {
            runTest { awaitProviderWrites({ emptyList() }, { null }, { false }) {} }
        }
    }
}
