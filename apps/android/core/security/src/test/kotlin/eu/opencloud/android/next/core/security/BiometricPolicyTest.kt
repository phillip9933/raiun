package eu.opencloud.android.next.core.security

import android.app.KeyguardManager
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BiometricPolicyTest {
    @Test fun biometricPreferenceNeverCreatesAnAuthenticationGrant() {
        val context = RuntimeEnvironment.getApplication()
        val lock = AppLock(context)
        Shadows.shadowOf(context.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        assertFalse(lock.biometricEnabled)
        lock.authenticated()
        lock.setEnabled(true)
        lock.preferences
            .edit()
            .putBoolean("biometric", true)
            .commit()
        lock.lock()
        try {
            assertFalse(lock.canOpenApp())
            assertFalse(lock.canOpenDocuments())
            assertThrows(IllegalStateException::class.java) { lock.setBiometricEnabled(false) }
        } finally {
            lock.preferences
                .edit()
                .clear()
                .commit()
            lock.lock()
        }
    }
}
