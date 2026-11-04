package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.model.auth.PkceRequest
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.PendingOidcLogin
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class OidcCallbackTest {
    private val pending =
        PendingOidcLogin(
            "https://cloud.example",
            OidcConfiguration(
                "https://id.example/tenant",
                "https://id.example/auth",
                "https://id.example/token",
                null,
                "mobile",
                listOf("openid"),
                authorizationResponseIssParameterSupported = true,
            ),
            PkceRequest("https://id.example/auth", "state", "verifier"),
            1_000,
        )

    @Test fun `encoded issuer and code are decoded once before exchange`() {
        var consumed = false
        val result =
            processOidcCallback(
                callback("iss=https%3A%2F%2Fid.example%2Ftenant&code=one%2Btwo"),
                consumePending = { state ->
                    assertEquals("state", state)
                    assertFalse(consumed)
                    consumed = true
                    pending
                },
                exchange = { login, code ->
                    assertEquals(pending, login)
                    assertEquals("one+two", code)
                    "session"
                },
            )
        assertEquals(OidcCallbackResult.Completed("session"), result)
    }

    @Test fun `missing blank duplicate and wrong issuer never reach the token endpoint`() {
        MockWebServer().use { tokenServer ->
            tokenServer.enqueue(MockResponse().setBody("unexpected"))
            listOf(
                "code=code",
                "iss=&code=code",
                "iss=https://id.example/tenant&iss=https://id.example/tenant&code=code",
                "iss=https://wrong.example&code=code",
                "iss=https://ID.example/tenant&code=code",
                "iss=https://id.example:443/tenant&code=code",
                "iss=https://id.example/tenant/&code=code",
                "error=access_denied",
                "iss=https://wrong.example&error=access_denied",
            ).forEach { query ->
                assertThrows(OidcCallbackIssuerException::class.java) {
                    processOidcCallback(callback(query), { pending }) { _, _ ->
                        OkHttpClient()
                            .newCall(
                                Request.Builder().url(tokenServer.url("token")).build(),
                            ).execute()
                            .close()
                    }
                }
            }
            assertEquals(0, tokenServer.requestCount)
        }
    }

    @Test fun `verified error and duplicate or missing code do not exchange`() {
        listOf(
            "error=access_denied",
            "error=access_denied&code=code",
            "code=one&code=two",
            "code=",
            "unused=value",
        ).forEach { query ->
            val result =
                processOidcCallback(callback("iss=https://id.example/tenant&$query"), { pending }) { _, _ ->
                    error("No exchange is permitted")
                }
            assertEquals(OidcCallbackResult.Rejected, result)
        }
    }

    @Test fun `invalid redirect duplicate state and fragment never consume pending state`() {
        listOf(
            "evil://oauth?state=state",
            "app.raiun.cloud://other?state=state",
            "app.raiun.cloud://oauth/path?state=state",
            "app.raiun.cloud://oauth?state=state#fragment",
            "app.raiun.cloud://oauth?state=state&state=state",
            "app.raiun.cloud://oauth?state=",
        ).forEach { uri ->
            assertThrows(OpenCloudException::class.java) {
                processOidcCallback(uri, { error("Must not consume") }) { _, _ -> error("Must not exchange") }
            }
        }
    }

    @Test fun `consumed or expired pending login never exchanges`() {
        val result =
            processOidcCallback(callback("iss=https://id.example/tenant&code=code"), { null }) { _, _ ->
                error("Must not exchange")
            }
        assertEquals(OidcCallbackResult.Expired, result)
    }

    @Test fun `matching callback is consumed once before exchange and cannot replay`() {
        var stored: PendingOidcLogin? = pending
        var exchanges = 0
        val consume: (String) -> PendingOidcLogin? = { state ->
            stored?.takeIf { it.request.state == state }.also { stored = null }
        }
        val exchange: (PendingOidcLogin, String) -> Unit = { _, _ ->
            assertEquals(null, stored)
            exchanges++
        }
        val uri = callback("iss=https://id.example/tenant&code=code")
        assertEquals(OidcCallbackResult.Completed(Unit), processOidcCallback(uri, consume, exchange))
        assertEquals(OidcCallbackResult.Expired, processOidcCallback(uri, consume, exchange))
        assertEquals(1, exchanges)
    }

    @Test fun `provider without advertised response issuer supports legacy success and error callbacks`() {
        val legacy =
            pending.copy(
                configuration = pending.configuration.copy(authorizationResponseIssParameterSupported = false),
            )
        assertEquals(
            OidcCallbackResult.Completed("session"),
            processOidcCallback(callback("code=legacy-code"), { legacy }) { _, code ->
                assertEquals("legacy-code", code)
                "session"
            },
        )
        assertEquals(
            OidcCallbackResult.Rejected,
            processOidcCallback(callback("error=access_denied"), { legacy }) { _, _ -> error("Must not exchange") },
        )
    }

    @Test fun `unadvertised issuer is accepted only when unique nonblank and exactly matching`() {
        val legacy =
            pending.copy(
                configuration = pending.configuration.copy(authorizationResponseIssParameterSupported = false),
            )
        assertEquals(
            OidcCallbackResult.Completed("session"),
            processOidcCallback(callback("iss=https://id.example/tenant&code=code"), { legacy }) { _, _ -> "session" },
        )
        MockWebServer().use { tokenServer ->
            tokenServer.enqueue(MockResponse().setBody("unexpected"))
            listOf(
                "iss=&code=code",
                "iss=https://wrong.example&code=code",
                "iss=https://id.example/tenant&iss=https://id.example/tenant&code=code",
                "iss=https://wrong.example&error=access_denied",
            ).forEach { query ->
                assertThrows(OidcCallbackIssuerException::class.java) {
                    processOidcCallback(callback(query), { legacy }) { _, _ ->
                        OkHttpClient()
                            .newCall(
                                Request.Builder().url(tokenServer.url("token")).build(),
                            ).execute()
                            .close()
                    }
                }
            }
            assertEquals(0, tokenServer.requestCount)
        }
    }

    private fun callback(query: String) = "app.raiun.cloud://oauth?state=state&$query"
}
