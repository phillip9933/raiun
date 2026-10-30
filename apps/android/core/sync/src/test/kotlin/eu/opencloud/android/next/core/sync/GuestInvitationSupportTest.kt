package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class GuestInvitationSupportTest {
    private val advertised = ServerCapabilities("0.1.0", true, true, true, false, guestLinksEnabled = true)

    @Test
    fun `explicit guest support works with compatibility or absent version`() {
        for (version in listOf("0.1.0", "9.0.0", null, "development")) {
            requireGuestInvitationSupport(advertised.copy(version = version))
        }
    }

    @Test
    fun `product version cannot override missing or disabled guest or sharing support`() {
        val missing = ServerCapabilities("9.0.0", true, true, true, false)
        for (capabilities in listOf(
            missing,
            advertised.copy(guestLinksEnabled = false),
            advertised.copy(sharingEnabled = false),
        )) {
            val failure = assertThrows(OpenCloudException::class.java) { requireGuestInvitationSupport(capabilities) }
            assertEquals(OpenCloudError.Unsupported, failure.error)
        }
    }

    @Test
    fun `runtime capability refresh retains guest flag and expires it without database persistence`() =
        runTest {
            var now = 1000L
            var calls = 0
            val account = AccountEntity("a", "https://cloud.example", "user", "User", "OIDC", false)
            val repository =
                CapabilityRepository(AppClock { now }) { _, _ ->
                    calls++
                    advertised.copy(guestLinksEnabled = calls == 1)
                }
            assertTrue(repository.refresh(account, "synthetic") { true }.guestLinksEnabled)
            requireGuestInvitationSupport(repository.refresh(account, "synthetic") { true })
            assertEquals(1, calls)
            now += 300_000
            val refreshed = repository.refresh(account, "synthetic") { true }
            assertFalse(refreshed.guestLinksEnabled)
            val failure = assertThrows(OpenCloudException::class.java) { requireGuestInvitationSupport(refreshed) }
            assertEquals(OpenCloudError.Unsupported, failure.error)
            assertEquals(2, calls)
        }
}
