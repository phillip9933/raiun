package eu.opencloud.android.next.core.datastore

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DiagnosticHistoryTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun `history is bounded excludes arbitrary text and clears`() {
        val file = temporary.newFile()
        file.writeText("Bearer secret\nhttps://private.example/path\n1 FAILED")
        val history = DiagnosticHistory(file)
        assertEquals("1 FAILED", history.read())
        repeat(150) { history.record(TransferDiagnostic.SUCCEEDED, it.toLong() + 2) }
        val lines = history.read().lines()
        assertEquals(100, lines.size)
        assertEquals("52 SUCCEEDED", lines.first())
        assertFalse(file.readText().contains("secret"))
        history.clear()
        assertEquals("", history.read())
        assertFalse(file.exists())
    }

    @Test fun `oversized history is discarded without unbounded parsing`() {
        val file = temporary.newFile()
        file.writeText("x".repeat(20_000))
        val history = DiagnosticHistory(file)
        assertEquals("", history.read())
        history.record(TransferDiagnostic.RETRY, 1)
        assertEquals("1 RETRY", history.read())
    }
}
