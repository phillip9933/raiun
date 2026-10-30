package eu.opencloud.android.next.feature.transfers

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class TransferDiagnosticsTest {
    @Test fun `diagnostics accept known categories and bounded numeric HTTP status`() {
        assertEquals("TIMEOUT", safeTransferDiagnosticCode("TIMEOUT"))
        assertEquals("SERVER_502", safeTransferDiagnosticCode("SERVER_502"))
        assertEquals("LOCAL_STORAGE_WRITE_FAILED", safeTransferDiagnosticCode("LOCAL_STORAGE_WRITE_FAILED"))
        assertEquals("ENCRYPTED_OFFLINE_INDEX_FULL", safeTransferDiagnosticCode("ENCRYPTED_OFFLINE_INDEX_FULL"))
    }

    @Test fun `diagnostics reject arbitrary database text and invalid status codes`() {
        listOf(
            null,
            "Bearer secret",
            "https://private.test/file",
            "SECRET_TOKEN",
            "HTTP_999",
            "SERVER_502 body",
        ).forEach {
            assertNull(safeTransferDiagnosticCode(it))
        }
    }
}
