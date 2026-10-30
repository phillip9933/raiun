package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.safeMessage
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TransferErrorPolicyTest {
    @Test fun `encrypted offline index capacity requires cleanup before retry`() {
        val error = OpenCloudError.EncryptedOfflineIndexFull
        org.junit.Assert.assertEquals("ENCRYPTED_OFFLINE_INDEX_FULL", error.diagnosticCode())
        assertFalse(error.canRetryTransfer(0))
        assertFalse(error.safeMessage().contains("server", ignoreCase = true))
        assertFalse(error.safeMessage().contains("device storage", ignoreCase = true))
        assertTrue(error.safeMessage().contains("this location"))
    }

    @Test fun `oversized listing is actionable and never automatically retried`() {
        val error = OpenCloudError.DirectoryListingTooLarge
        org.junit.Assert.assertEquals("DIRECTORY_LISTING_TOO_LARGE", error.diagnosticCode())
        assertFalse(error.canRetryTransfer(0))
        org.junit.Assert.assertEquals(
            "The server returned a folder listing larger than Raiun can safely process. Try opening a smaller subfolder.",
            error.safeMessage(),
        )
    }

    @org.junit.Test fun `not ready is bounded and respects retry after`() {
        val error = OpenCloudError.NotReady(120)
        org.junit.Assert.assertTrue(error.canRetryTransfer(1))
        org.junit.Assert.assertFalse(error.canRetryTransfer(5))
        org.junit.Assert.assertEquals(121000L, error.retryDeadline(1000L))
    }

    @Test fun `unsent route changes retry but unavailable identity requires user action`() {
        assertTrue(OpenCloudError.NetworkRouteChanged.canRetryTransfer(0))
        assertFalse(OpenCloudError.NetworkRouteChanged.canRetryTransfer(5))
        assertFalse(OpenCloudError.ClientCertificateRequired.canRetryTransfer(0))
        org.junit.Assert.assertEquals("NETWORK_ROUTE_CHANGED", OpenCloudError.NetworkRouteChanged.diagnosticCode())
        org.junit.Assert.assertEquals(
            "CLIENT_CERTIFICATE_REQUIRED",
            OpenCloudError.ClientCertificateRequired.diagnosticCode(),
        )
    }

    @Test fun `connectivity retries are bounded`() {
        assertTrue(OpenCloudError.Connectivity.canRetryTransfer(0))
        assertTrue(OpenCloudError.Connectivity.canRetryTransfer(4))
        assertFalse(OpenCloudError.Connectivity.canRetryTransfer(5))
    }

    @Test fun `ambiguous mutations and server delay never trigger blind retry`() {
        listOf(
            OpenCloudError.Timeout,
            OpenCloudError.Unknown,
            OpenCloudError.AuthenticationRequired,
            OpenCloudError.AccessDenied,
            OpenCloudError.Conflict,
            OpenCloudError.PreconditionFailed,
            OpenCloudError.QuotaExceeded,
            OpenCloudError.Trust,
            OpenCloudError.ServerFailure(503, 3600),
        ).forEach { assertFalse(it.canRetryTransfer(0)) }
    }

    @Test fun `transient server failure retries only safe transfers and respects server delay`() {
        val transfer =
            TransferEntity(
                id = "id",
                accountId = "account",
                spaceId = "space",
                resourceId = null,
                direction = "UPLOAD",
                sourceUri = null,
                destinationPath = "/file",
                displayName = "file",
                mimeType = null,
                bytesTotal = 100,
                createdAtEpochMillis = 0,
                updatedAtEpochMillis = 0,
            )
        val error = OpenCloudError.ServerFailure(503, 120)
        assertTrue(error.canRetryTransfer(transfer))
        assertFalse(error.canRetryTransfer(transfer.copy(overwrite = true)))
        assertTrue(error.canRetryTransfer(transfer.copy(overwrite = true, expectedETag = "\"original\"")))
        assertTrue(error.canRetryTransfer(transfer.copy(direction = "DOWNLOAD", overwrite = true)))
        assertFalse(error.canRetryTransfer(transfer.copy(attemptCount = 5)))
        assertFalse(OpenCloudError.InvalidResponse.canRetryTransfer(transfer))
        org.junit.Assert.assertEquals(121000L, error.retryDeadline(1000))
    }

    @Test fun `gateway failure from a new upload is retryable but replacement needs a validator`() {
        val transfer =
            TransferEntity(
                id = "upload",
                accountId = "account",
                spaceId = "space",
                resourceId = null,
                direction = "UPLOAD",
                sourceUri = "content://source",
                destinationPath = "/file",
                displayName = "file",
                mimeType = null,
                bytesTotal = 149_000_000,
                createdAtEpochMillis = 0,
                updatedAtEpochMillis = 0,
            )
        val badGateway = OpenCloudError.ServerFailure(502, null)
        assertTrue(badGateway.canRetryTransfer(transfer))
        assertFalse(badGateway.canRetryTransfer(transfer.copy(overwrite = true)))
        assertTrue(badGateway.canRetryTransfer(transfer.copy(overwrite = true, expectedETag = "\"v1\"")))
    }

    @Test fun `rate limits have durable bounded retry deadlines`() {
        val error = OpenCloudError.RateLimited(3600)
        assertTrue(error.canRetryTransfer(1))
        assertFalse(error.canRetryTransfer(5))
        org.junit.Assert.assertEquals(3_601_000L, error.retryDeadline(1000L))
        org.junit.Assert.assertEquals(Long.MAX_VALUE, OpenCloudError.RateLimited(Long.MAX_VALUE).retryDeadline(1000))
    }
}
