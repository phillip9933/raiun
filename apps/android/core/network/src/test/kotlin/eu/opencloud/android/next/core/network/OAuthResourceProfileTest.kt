package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class OAuthResourceProfileTest {
    @Test fun `OCS identity requires a real nonempty string rather than null or coercion`() {
        MockWebServer().use { server ->
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            listOf("null", "42", "true", "\"\"", "{}").forEach { id ->
                server.enqueue(MockResponse().setBody("""{"ocs":{"data":{"id":$id}}}"""))
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        api.bearerProfile(server.url("/").toString().trimEnd('/'), "valid-token")
                    }
                assertEquals(OpenCloudError.InvalidResponse, failure.error)
            }
        }
    }

    @Test fun `nullable optional profile fields keep the server identity unchanged`() {
        MockWebServer().use { server ->
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            server.enqueue(
                MockResponse().setBody("""{"ocs":{"data":{"id":"User-MiXeD","display-name":null,"email":null}}}"""),
            )
            val profile = api.bearerProfile(server.url("/").toString().trimEnd('/'), "valid-token")
            assertEquals("User-MiXeD", profile.id)
            assertEquals("User-MiXeD", profile.displayName)
            assertNull(profile.email)
        }
    }

    @Test fun `malformed discovery structures fail through fixed metadata errors`() {
        MockWebServer().use { server ->
            val api = OpenCloudApi(OkHttpClient(), endpoints = EndpointPolicy(allowLoopbackHttp = true))
            listOf(
                "[]",
                "{",
                """{"links":true}""",
                """{"links":[false]}""",
                """{"links":[{"rel":{}}]}""",
            ).forEach { body ->
                server.enqueue(MockResponse().setBody(body))
                val failure = assertThrows(OpenCloudException::class.java) { api.webFinger(server.url("/").toString()) }
                assertEquals(OpenCloudError.InvalidResponse, failure.error)
            }
        }
    }
}
