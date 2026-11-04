package eu.opencloud.android.next.feature.auth

import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class AuthRemovalPendingErrorTest {
    @Test
    @Config(qualifiers = "en")
    fun pendingCleanupUsesLocalizedActionableMessage() {
        val context = RuntimeEnvironment.getApplication()
        assertEquals(
            "Account cleanup is still pending on this phone. " +
                "Open Accounts to check cleanup before signing in again.",
            AccountRemovalPendingException().toAuthError(context, "certificate-only message"),
        )
    }
}
