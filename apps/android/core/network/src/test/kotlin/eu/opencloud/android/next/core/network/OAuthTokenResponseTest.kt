package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class OAuthTokenResponseTest {
    private val json = Json { ignoreUnknownKeys = true }

    @Test fun `valid token response keeps opaque values and canonicalizes only header scheme`() {
        val value =
            parse(
                """{"access_token":"AbC-._~+/MiXeD==","token_type":"bearer","refresh_token":"Refresh-MiXeD","scope":"openid groups custom,scope","expires_in":300}""",
            )
        assertEquals("Bearer AbC-._~+/MiXeD==", value.bearerAuthorizationHeader())
        assertEquals("bearer", value.tokenType)
        assertEquals("Refresh-MiXeD", value.refreshToken)
        assertEquals("openid groups custom,scope", value.scope)
        assertEquals(1300L, value.expiresAtEpochSeconds)
    }

    @Test fun `required token fields reject absent null nonstring and unsupported values`() {
        listOf(
            """{"token_type":"Bearer"}""",
            """{"access_token":null,"token_type":"Bearer"}""",
            """{"access_token":123,"token_type":"Bearer"}""",
            """{"access_token":"" ,"token_type":"Bearer"}""",
            """{"access_token":"a b","token_type":"Bearer"}""",
            """{"access_token":"a=b","token_type":"Bearer"}""",
            """{"access_token":"token"}""",
            """{"access_token":"token","token_type":null}""",
            """{"access_token":"token","token_type":true}""",
            """{"access_token":"token","token_type":"Basic"}""",
            """{"access_token":"token","token_type":"Bearer "}""",
        ).forEach(::assertInvalid)
    }

    @Test fun `omitted lifetime uses documented fallback but malformed present lifetime is rejected`() {
        assertEquals(4600L, parse("""{"access_token":"token","token_type":"Bearer"}""").expiresAtEpochSeconds)
        listOf("null", "true", "{}", "[]", "1.5", "-1", "\"later\"", "\" 300\"", "9223372036854775808").forEach {
            assertInvalid("""{"access_token":"token","token_type":"Bearer","expires_in":$it}""")
        }
    }

    @Test fun `integer string lifetimes remain compatible and excessive lifetime is bounded`() {
        assertEquals(
            1300L,
            parse("""{"access_token":"token","token_type":"Bearer","expires_in":"300"}""").expiresAtEpochSeconds,
        )
        assertEquals(
            31537000L,
            parse(
                """{"access_token":"token","token_type":"Bearer","expires_in":9223372036854775807}""",
            ).expiresAtEpochSeconds,
        )
        assertEquals(
            1000L,
            parse("""{"access_token":"token","token_type":"Bearer","expires_in":0}""").expiresAtEpochSeconds,
        )
    }

    @Test fun `optional refresh metadata cannot poison rotation or serialized credentials`() {
        listOf("\"\"", "\" \"", "123", "{}", "\"bad\\u0000value\"", "\"bad\\nvalue\"").forEach {
            assertInvalid("""{"access_token":"token","token_type":"Bearer","refresh_token":$it}""")
        }
        assertNull(parse("""{"access_token":"token","token_type":"Bearer"}""").refreshToken)
        assertNull(parse("""{"access_token":"token","token_type":"Bearer","refresh_token":null}""").refreshToken)
    }

    @Test fun `scope preserves custom values and rejects malformed metadata`() {
        listOf(
            "true",
            "42",
            "{}",
            "\"openid\\nprofile\"",
            "\"\"",
            "\" \"",
            "\"openid \"",
            "\"openid  profile\"",
        ).forEach {
            assertInvalid("""{"access_token":"token","token_type":"Bearer","scope":$it}""")
        }
        assertNull(parse("""{"access_token":"token","token_type":"Bearer","scope":null}""").scope)
    }

    @Test fun `malformed response does not expose payload or parsing exceptions`() {
        listOf("[]", "null", "\"private-token\"", "{\"access_token\":\"private-token\",").forEach(::assertInvalid)
    }

    @Test fun `expiry overflow fails safely`() {
        val failure =
            assertThrows(OpenCloudException::class.java) {
                parseOAuthTokenResponse(
                    """{"access_token":"token","token_type":"Bearer","expires_in":300}""",
                    Long.MAX_VALUE,
                    json,
                )
            }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
    }

    private fun parse(body: String) = parseOAuthTokenResponse(body, 1000, json)

    private fun assertInvalid(body: String) {
        val failure = assertThrows(OpenCloudException::class.java) { parse(body) }
        assertEquals(OpenCloudError.InvalidResponse, failure.error)
        assertEquals("The server returned incomplete or unexpected metadata.", failure.message)
    }
}
