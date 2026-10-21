package eu.opencloud.android.next

import android.content.Context
import android.content.Intent
import android.content.pm.ProviderInfo
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.documentsprovider.OpenCloudDocumentsProvider
import eu.opencloud.android.next.core.security.AppLock
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/** Verifies enforcement on Android without changing the emulator's screen-lock credentials. */
class SecurityAccessTest {
    @Test fun lockedAppAndProviderDenyAccessUntilSystemAuthentication() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        // This disposable test installation must not be obscured by the first-run notification prompt.
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            instrumentation.uiAutomation.grantRuntimePermission(
                context.packageName,
                android.Manifest.permission.POST_NOTIFICATIONS,
            )
        }
        val preferences = context.getSharedPreferences("app-lock", Context.MODE_PRIVATE)
        val wasEnabled = preferences.getBoolean("enabled", false)
        val protectedDocuments = preferences.getBoolean("documents", true)
        val lock = AppLock(context)
        lock.lock()
        preferences
            .edit()
            .putBoolean("enabled", true)
            .putBoolean("documents", true)
            .commit()
        val unlockMonitor = instrumentation.addMonitor(DeviceUnlockActivity::class.java.name, null, false)
        val activity =
            instrumentation.startActivitySync(
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        try {
            cancelAutomaticUnlock(instrumentation, unlockMonitor, lock.deviceSecure)
            instrumentation.waitForIdleSync()
            val deadline = android.os.SystemClock.uptimeMillis() + 5_000
            var lockVisible = false
            while (!lockVisible && android.os.SystemClock.uptimeMillis() < deadline) {
                lockVisible = hasLockText(instrumentation.uiAutomation.rootInActiveWindow)
                if (!lockVisible) android.os.SystemClock.sleep(100)
            }
            org.junit.Assert.assertTrue("The app must display its lock screen", lockVisible)
            org.junit.Assert.assertFalse(lock.canOpenApp())
            val provider = OpenCloudDocumentsProvider()
            provider.attachInfo(
                context,
                ProviderInfo().apply {
                    authority = context.packageName + ".security-test"
                    exported = true
                    grantUriPermissions = true
                    readPermission = "android.permission.MANAGE_DOCUMENTS"
                    writePermission = "android.permission.MANAGE_DOCUMENTS"
                },
            )
            provider.queryRoots(null).use { assertEquals(1, it.count) }
            assertThrows(android.app.AuthenticationRequiredException::class.java) {
                provider.queryChildDocuments("locked", null, sortOrder = null)
            }
            assertThrows(
                android.app.AuthenticationRequiredException::class.java,
            ) { provider.openDocument("locked", "r", null) }
        } finally {
            instrumentation.removeMonitor(unlockMonitor)
            instrumentation.runOnMainSync { activity.finish() }
            preferences
                .edit()
                .putBoolean("enabled", wasEnabled)
                .putBoolean("documents", protectedDocuments)
                .commit()
            lock.lock()
        }
    }
}

private fun hasLockText(node: android.view.accessibility.AccessibilityNodeInfo?): Boolean {
    if (node == null) return false
    if (node.text?.toString() == "Raiun is locked") return true
    return (0 until node.childCount).any { hasLockText(node.getChild(it)) }
}
