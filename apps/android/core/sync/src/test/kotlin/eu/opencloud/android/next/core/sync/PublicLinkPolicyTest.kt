package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import org.junit.Assert.assertThrows
import org.junit.Test
import java.time.LocalDate

class PublicLinkPolicyTest {
    private val today = LocalDate.of(2026, 9, 12)
    private val account =
        AccountEntity(
            "a",
            "https://cloud.example",
            "user",
            "User",
            "OIDC",
            false,
            publicLinkPasswordEnforced = true,
            publicLinkExpirationEnforced = true,
            publicLinkExpirationDays = 7,
        )

    @Test
    fun `stronger policy rejects missing password and missing or excessive expiration`() {
        assertThrows(IllegalArgumentException::class.java) {
            validatePublicLinkPolicy(account, null, today.plusDays(1), today = today)
        }
        assertThrows(IllegalArgumentException::class.java) {
            validatePublicLinkPolicy(account, "secret", null, today = today)
        }
        assertThrows(IllegalArgumentException::class.java) {
            validatePublicLinkPolicy(account, "secret", today.plusDays(8), today = today)
        }
        validatePublicLinkPolicy(account, "secret", today.plusDays(7), today = today)
    }

    @Test
    fun `update preserves an omitted password but cannot explicitly clear an enforced password`() {
        validatePublicLinkPolicy(account, null, today.plusDays(1), updating = true, today = today)
        assertThrows(IllegalArgumentException::class.java) {
            validatePublicLinkPolicy(account, "", today.plusDays(1), updating = true, today = today)
        }
    }
}
