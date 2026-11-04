package eu.opencloud.android.next.feature.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.CancellationException

class AuthErrorTest {
    @Test fun `pending local cleanup explains the next action without server denial`() {
        assertEquals(
            "Account cleanup is still pending on this phone. " +
                "Open Accounts to check cleanup before signing in again.",
            AccountRemovalPendingException().toAuthError(),
        )
    }

    @Test fun `transport errors retain actionable safe messages`() {
        assertEquals("The connection timed out.", SocketTimeoutException("private host").toAuthError())
        assertEquals("The server could not be reached.", UnknownHostException("private host").toAuthError())
        assertEquals("The operation could not be completed.", IllegalStateException("private data").toAuthError())
        assertThrows(CancellationException::class.java) { CancellationException().toAuthError() }
    }
}
