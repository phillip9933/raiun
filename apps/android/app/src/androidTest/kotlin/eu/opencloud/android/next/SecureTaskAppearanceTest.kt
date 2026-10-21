package eu.opencloud.android.next

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Build
import android.os.SystemClock
import android.view.WindowManager
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.datastore.Appearance
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.security.AppLock
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Checks the actual task metadata Android uses to draw redacted Recents snapshots. */
class SecureTaskAppearanceTest {
    @Test fun lockedDarkTaskKeepsDarkRecentsBackground() {
        assumeTrue(Build.VERSION.SDK_INT >= 33)
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        instrumentation.uiAutomation.grantRuntimePermission(
            context.packageName,
            android.Manifest.permission.POST_NOTIFICATIONS,
        )
        val settings = SettingsRepository.create(context)
        val previousAppearance = runBlocking { settings.settings.first().appearance }
        val lock = AppLock(context)
        val previousEnabled = lock.enabled
        runBlocking { settings.setAppearance(Appearance.DARK) }
        lock.preferences
            .edit()
            .putBoolean("enabled", true)
            .commit()
        lock.lock()
        val unlockMonitor = instrumentation.addMonitor(DeviceUnlockActivity::class.java.name, null, false)
        val activity =
            instrumentation.startActivitySync(
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        try {
            cancelAutomaticUnlock(instrumentation, unlockMonitor, lock.deviceSecure)
            val manager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val expected = Color.rgb(16, 20, 22)
            val deadline = SystemClock.uptimeMillis() + 5000
            var actual = 0
            while (actual != expected && SystemClock.uptimeMillis() < deadline) {
                instrumentation.waitForIdleSync()
                actual =
                    manager.appTasks
                        .first { it.taskInfo.taskId == activity.taskId }
                        .taskInfo.taskDescription
                        ?.backgroundColor ?: 0
                if (actual != expected) SystemClock.sleep(100)
            }
            assertEquals(expected, actual)
            instrumentation.runOnMainSync {
                assertTrue(activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            }
        } finally {
            instrumentation.removeMonitor(unlockMonitor)
            instrumentation.runOnMainSync { activity.finish() }
            runBlocking { settings.setAppearance(previousAppearance) }
            lock.preferences
                .edit()
                .putBoolean("enabled", previousEnabled)
                .commit()
            lock.lock()
        }
    }
}
