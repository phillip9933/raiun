package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.TransferEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UploadProtocolTest {
    private val pending =
        TransferEntity(
            id = "upload",
            accountId = "account",
            spaceId = "space",
            resourceId = null,
            direction = "UPLOAD",
            sourceUri = "content://source/file",
            destinationPath = "/file",
            displayName = "file",
            mimeType = null,
            bytesTotal = 20L * 1024 * 1024,
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    @Test fun `new files and conditional edits never use unconditional resumable writes`() {
        assertFalse(pending.canUseTusUpload(true))
        assertFalse(pending.copy(overwrite = true, expectedETag = "\"version\"").canUseTusUpload(true))
        assertTrue(pending.copy(overwrite = true).canUseTusUpload(true))
        assertFalse(pending.copy(overwrite = true).canUseTusUpload(false))
        assertFalse(pending.copy(overwrite = true, bytesTotal = 0).canUseTusUpload(true))
    }

    @Test fun `legacy sessions lose the unsafe address without losing verification evidence`() {
        val legacy =
            pending.copy(
                tusUrl = "https://example.test/session",
                tusOffset = pending.bytesTotal,
                bytesTransferred = pending.bytesTotal,
                verificationPending = true,
                attemptCount = 2,
            )
        assertEquals(legacy.copy(tusUrl = null, tusOffset = 0), legacy.withoutUnprotectedTusSession())
        val replacement = legacy.copy(overwrite = true)
        assertEquals(replacement, replacement.withoutUnprotectedTusSession())
        val edit = replacement.copy(expectedETag = "\"version\"")
        assertEquals(edit.copy(tusUrl = null, tusOffset = 0), edit.withoutUnprotectedTusSession())
    }

    @Test fun `manual retry retains evidence that the final upload bytes may have reached the server`() {
        val uncertain = pending.copy(attemptCount = 3, bytesTransferred = pending.bytesTotal)
        assertTrue(uncertain.requiresUploadVerificationOnRetry())
        assertTrue(uncertain.copy(verificationPending = true, bytesTransferred = 0).requiresUploadVerificationOnRetry())
        assertFalse(
            pending.copy(attemptCount = 0, bytesTransferred = pending.bytesTotal).requiresUploadVerificationOnRetry(),
        )
    }
}
