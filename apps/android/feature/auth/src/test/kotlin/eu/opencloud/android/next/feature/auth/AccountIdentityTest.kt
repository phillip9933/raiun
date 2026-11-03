package eu.opencloud.android.next.feature.auth

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class AccountIdentityTest {
    @Test fun `case sensitive deployments have independent identities`() {
        assertNotEquals(
            resolveAccountId("https://cloud.example/Team", "alice") { null },
            resolveAccountId("https://cloud.example/team", "alice") { null },
        )
    }

    @Test fun `existing mixed case deployment keeps credentials and data identity`() {
        val server = "https://cloud.example/Team"
        val oldId = "https://cloud.example/team#alice"
        assertEquals(
            oldId,
            resolveAccountId(server, "alice") { id ->
                assertEquals(oldId, id)
                server to "alice"
            },
        )
    }

    @Test fun `another deployment cannot adopt the legacy credential slot`() {
        val server = "https://cloud.example/team"
        val expected = resolveAccountId(server, "alice") { null }
        assertEquals(expected, resolveAccountId(server, "alice") { "https://cloud.example/Team" to "alice" })
        assertNotEquals("$server#alice", expected)
    }

    @Test fun `normalization preserves host and port equivalence`() {
        assertEquals(
            resolveAccountId("https://CLOUD.example:443/Team/", "alice") { null },
            resolveAccountId("https://cloud.example/Team", "alice") { null },
        )
    }
}
