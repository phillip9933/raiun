package eu.opencloud.android.next.core.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.concurrent.CancellationException
import javax.net.ssl.SSLHandshakeException

class OpenCloudErrorTest {
    private val clock = Clock.fixed(Instant.parse("2026-09-12T00:00:00Z"), ZoneOffset.UTC)

    @Test fun `HTTP failures remain distinct`() {
        assertEquals(OpenCloudError.AuthenticationRequired, httpError(401))
        assertEquals(OpenCloudError.AccessDenied, httpError(403))
        assertEquals(OpenCloudError.Conflict, httpError(409))
        assertEquals(OpenCloudError.PreconditionFailed, httpError(412))
        assertEquals(OpenCloudError.NotReady(12), httpError(425, 12))
        assertEquals(OpenCloudError.RateLimited(12), httpError(429, 12))
        assertEquals(OpenCloudError.QuotaExceeded, httpError(507))
        assertEquals(OpenCloudError.ServerFailure(503, 60), httpError(503, 60))
    }

    @Test fun `Retry-After accepts seconds and dates without overflow or negative delay`() {
        assertEquals(60L, parseRetryAfter("60", clock))
        assertEquals(60L, parseRetryAfter("Sat, 12 Sep 2026 00:01:00 GMT", clock))
        assertEquals(0L, parseRetryAfter("Fri, 11 Sep 2026 00:00:00 GMT", clock))
        assertEquals(Long.MAX_VALUE, parseRetryAfter("999999999999999999999999", clock))
        assertNull(parseRetryAfter("-1", clock))
        assertNull(parseRetryAfter("1.5", clock))
        assertNull(parseRetryAfter("secret", clock))
        assertNull(parseRetryAfter(null, clock))
    }

    @Test fun `transport errors do not retain untrusted text`() {
        assertEquals(OpenCloudError.Connectivity, UnknownHostException("private host").toOpenCloudError())
        assertEquals(OpenCloudError.Timeout, SocketTimeoutException("secret").toOpenCloudError())
        assertEquals(OpenCloudError.Trust, SSLHandshakeException("private certificate").toOpenCloudError())
        assertEquals(OpenCloudError.Unknown, IOException("private path").toOpenCloudError())
        val failure = TransferHttpException(403)
        assertEquals("Access was denied.", failure.message)
        assertNull(failure.cause)
    }

    @Test fun `download integrity has a distinct safe message`() {
        assertEquals(
            "The downloaded file could not be verified. Try downloading it again.",
            OpenCloudError.DownloadIntegrity.safeMessage(),
        )
        assertEquals(
            OpenCloudError.DownloadIntegrity,
            OpenCloudException(OpenCloudError.DownloadIntegrity).toOpenCloudError(),
        )
    }

    @Test fun `cancellation is rethrown unchanged`() {
        val cancelled = CancellationException("cancelled")
        assertSame(cancelled, assertThrows(CancellationException::class.java) { cancelled.toOpenCloudError() })
    }
}
