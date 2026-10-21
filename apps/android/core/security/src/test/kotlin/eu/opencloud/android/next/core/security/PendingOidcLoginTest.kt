package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.model.auth.PkceRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class PendingOidcLoginTest {
    @Test fun `pending login survives serialization and expires within ten minutes`() {
        val login =
            PendingOidcLogin(
                "https://cloud.example",
                OidcConfiguration(
                    "https://id.example",
                    "https://id.example/auth",
                    "https://id.example/token",
                    null,
                    "registered-client",
                    listOf("openid", "offline_access"),
                ),
                PkceRequest("https://id.example/auth?state=unique", "unique", "private-verifier"),
                1_000,
            )
        assertEquals(login, PendingOidcLogin.decode(login.encode()))
        assertFalse(login.validAt(999))
        assertTrue(login.validAt(601_000))
        assertFalse(login.validAt(601_001))
    }
}
