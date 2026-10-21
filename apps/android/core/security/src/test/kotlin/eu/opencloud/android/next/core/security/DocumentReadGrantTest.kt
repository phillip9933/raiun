package eu.opencloud.android.next.core.security

import android.app.KeyguardManager
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowSystemClock
import java.time.Duration

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class DocumentReadGrantTest {
    @Test fun editGrantSurvivesPickerExpiryButCannotReviveAfterRelocking() {
        val context = RuntimeEnvironment.getApplication()
        val lock = AppLock(context)
        Shadows.shadowOf(context.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        lock.authenticated()
        lock.setEnabled(true)
        try {
            val edit = lock.beginDocumentEdit()
            ShadowSystemClock.advanceBy(Duration.ofSeconds(61))
            assertTrue(edit())
            assertThrows(IllegalStateException::class.java) { lock.beginDocumentEdit() }
            lock.lock()
            lock.authenticated()
            assertFalse(edit())
            assertTrue(lock.beginDocumentEdit()())
        } finally {
            lock.preferences
                .edit()
                .clear()
                .commit()
            lock.lock()
        }
    }

    @Test fun authorizedLongReadSurvivesPickerExpiryButNotScreenLock() {
        val context = RuntimeEnvironment.getApplication()
        val lock = AppLock(context)
        Shadows.shadowOf(context.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        lock.authenticated()
        lock.setEnabled(true)
        try {
            val read = lock.beginDocumentRead()
            ShadowSystemClock.advanceBy(Duration.ofSeconds(61))
            assertFalse(lock.canOpenDocuments())
            assertThrows(IllegalStateException::class.java) { lock.beginDocumentRead() }
            assertTrue(read())
            lock.lock()
            assertFalse(read())
            assertFalse(lock.canOpenDocuments())
            lock.authenticated()
            assertFalse(read())
            assertTrue(lock.beginDocumentRead()())
            lock.preferences
                .edit()
                .putBoolean("enabled", false)
                .commit()
            assertFalse(read())
        } finally {
            lock.preferences
                .edit()
                .clear()
                .commit()
            lock.lock()
        }
    }
}
