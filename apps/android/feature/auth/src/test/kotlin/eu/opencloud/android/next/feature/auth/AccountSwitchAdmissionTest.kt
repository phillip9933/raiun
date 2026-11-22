package eu.opencloud.android.next.feature.auth

import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.beginAccountRemoval
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.model.auth.Account
import eu.opencloud.android.next.core.model.auth.AuthenticationType
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class AccountSwitchAdmissionTest {
    @Test fun unavailableOrStaleSelectionKeepsCurrentAccount() =
        runBlocking {
            val app = RuntimeEnvironment.getApplication()
            val auth = AuthViewModel(app)
            val settings = SettingsRepository.create(app)
            withTimeout(10_000) { auth.state.first { !it.isRestoringSession } }
            val accounts = FileBrowserStore(FileBrowserDatabase.create(app))
            val current = Account("current", "https://example.test", "current", "Current", AuthenticationType.BASIC)
            val other = current.copy(id = "other", userId = "other", displayName = "Other")
            val capabilities = ServerCapabilities(null, false, false, false, false)
            accounts.saveAccount(current, capabilities)
            accounts.saveAccount(other, capabilities)
            try {
                assertTrue(auth.switchAccount(current.id))
                assertFalse(auth.switchAccount("missing"))
                assertFalse(auth.switchAccount(other.id) { false })
                assertTrue(accounts.beginAccountRemoval(other.id))
                assertFalse(auth.switchAccount(other.id))
                assertEquals(current.id, auth.state.value.activeAccountId)
                assertEquals(current.id, settings.settings.first().activeAccountId)
            } finally {
                accounts.removeAccount(current.id)
                accounts.removeAccount(other.id)
                settings.setActiveAccountId(null)
            }
        }
}
