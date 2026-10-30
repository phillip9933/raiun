package eu.opencloud.android.next.core.network

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class OidcFlowMetadataTest {
    @Test fun `public authorization code with S256 is supported with or without optional advertisements`() {
        validate("{}")
        validate(
            """{"response_types_supported":["code","code id_token"],"grant_types_supported":["authorization_code"],"code_challenge_methods_supported":["S256"]}""",
        )
    }

    @Test fun `contradictory flow metadata cannot silently downgrade the native public client`() {
        listOf(
            """{"response_types_supported":["token"]}""",
            """{"grant_types_supported":["client_credentials"]}""",
            """{"code_challenge_methods_supported":["plain"]}""",
            """{"code_challenge_methods_supported":[]}""",
        ).forEach { body ->
            val failure = assertThrows(OpenCloudException::class.java) { validate(body) }
            assertEquals(OpenCloudError.Unsupported, failure.error)
        }
    }

    @Test fun `malformed supported capability fields fail as metadata rather than provider strings`() {
        listOf(
            """{"response_types_supported":"code"}""",
            """{"grant_types_supported":[true]}""",
            """{"code_challenge_methods_supported":null}""",
            """{"code_challenge_methods_supported":["S256",{}]}""",
        ).forEach { body ->
            val failure = assertThrows(OpenCloudException::class.java) { validate(body) }
            assertEquals(OpenCloudError.InvalidResponse, failure.error)
        }
    }

    private fun validate(body: String) = validateOidcFlowMetadata(Json.parseToJsonElement(body).jsonObject)
}
