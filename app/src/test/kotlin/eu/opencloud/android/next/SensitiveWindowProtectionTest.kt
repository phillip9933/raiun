package eu.opencloud.android.next

import android.view.WindowManager
import androidx.activity.ComponentActivity
import eu.opencloud.android.next.core.security.AppLock
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SensitiveWindowProtectionTest {
    @Test fun lifecycleUpdateAndRepeatedReleaseCannotClearAnotherSensitiveScreen() {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        val activity = controller.get()
        val lock = AppLock(activity)
        lock.preferences
            .edit()
            .clear()
            .commit()
        val releaseFirst = SensitiveWindowProtection.acquire(activity)
        val releaseSecond = SensitiveWindowProtection.acquire(activity)
        try {
            SensitiveWindowProtection.update(activity)
            assertTrue(activity.secure())
            releaseFirst()
            releaseFirst()
            assertTrue(activity.secure())
            releaseSecond()
            assertFalse(activity.secure())
        } finally {
            releaseFirst()
            releaseSecond()
            controller.pause().stop().destroy()
        }
    }

    @Test fun releasingVaultProtectionPreservesEnabledAppLock() {
        val controller = Robolectric.buildActivity(ComponentActivity::class.java).setup()
        val activity = controller.get()
        val lock = AppLock(activity)
        lock.preferences
            .edit()
            .putBoolean("enabled", true)
            .commit()
        val release = SensitiveWindowProtection.acquire(activity)
        try {
            release()
            assertTrue(activity.secure())
            lock.preferences
                .edit()
                .putBoolean("enabled", false)
                .commit()
            SensitiveWindowProtection.update(activity)
            assertFalse(activity.secure())
        } finally {
            release()
            lock.preferences
                .edit()
                .clear()
                .commit()
            controller.pause().stop().destroy()
        }
    }

    private fun ComponentActivity.secure(): Boolean =
        window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0
}
