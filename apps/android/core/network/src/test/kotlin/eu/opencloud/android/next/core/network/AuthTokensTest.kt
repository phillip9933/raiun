package eu.opencloud.android.next.core.network

import eu.opencloud.android.next.core.model.auth.AuthTokens
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AuthTokensTest {
    @Test fun `bearer scheme casing is canonicalized for fresh and stored-shaped tokens`() {
        listOf("Bearer", "BEARER", "bEaReR").forEach { scheme ->
            assertEquals("Bearer opaque.Token-9", tokens(scheme, "opaque.Token-9").bearerAuthorizationHeader())
        }
    }

    @Test fun `opaque access token is preserved exactly`() {
        val token = "AbC-._~+/MixedCASE=="

        assertEquals("Bearer $token", tokens("bearer", token).bearerAuthorizationHeader())
    }

    @Test fun `unsupported and malformed token types fail safely`() {
        listOf("", " ", "Basic", "Bearer ", "Bearer\t", "Bearer extra").forEach { scheme ->
            assertInvalid(tokens(scheme, "opaque"))
        }
    }

    @Test fun `blank or control-bearing access tokens fail safely`() {
        listOf(
            "",
            "  ",
            "token\rInjected: yes",
            "token\nInjected: yes",
            "token\u0000tail",
            "token\tpart",
            "a b",
            "a=b",
            "é",
        ).forEach { token ->
            assertInvalid(tokens("Bearer", token))
        }
    }

    private fun assertInvalid(value: AuthTokens) {
        val failure = assertThrows(OpenCloudException::class.java) { value.bearerAuthorizationHeader() }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals("The server returned incomplete or unexpected metadata.", failure.message)
    }

    private fun tokens(
        tokenType: String,
        accessToken: String,
    ) = AuthTokens(accessToken, "refresh", 99, tokenType, null)
}
