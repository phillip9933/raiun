package eu.opencloud.android.next

import android.app.Instrumentation
import android.os.SystemClock
import android.view.KeyEvent
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue

/** Cancels the genuine system prompt without knowing or changing the emulator's credentials. */
internal fun cancelAutomaticUnlock(
    instrumentation: Instrumentation,
    monitor: Instrumentation.ActivityMonitor,
    secure: Boolean,
) {
    if (!secure) return
    assertNotNull("Locked entry should launch authentication automatically", monitor.waitForActivityWithTimeout(8_000))
    val deadline = SystemClock.uptimeMillis() + 8_000
    var systemPrompt = false
    while (!systemPrompt && SystemClock.uptimeMillis() < deadline) {
        val app =
            instrumentation.uiAutomation.rootInActiveWindow
                ?.packageName
                ?.toString()
        systemPrompt = app == "com.android.settings" || app == "com.android.systemui"
        if (!systemPrompt) SystemClock.sleep(100)
    }
    assertTrue("Expected Android authentication UI", systemPrompt)
    instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
    val returnDeadline = SystemClock.uptimeMillis() + 8_000
    var locked = false
    while (!locked && SystemClock.uptimeMillis() < returnDeadline) {
        locked = containsLockedText(instrumentation.uiAutomation.rootInActiveWindow)
        if (!locked) SystemClock.sleep(100)
    }
    assertTrue("Cancel must return to the locked app without another automatic prompt", locked)
}

private fun containsLockedText(node: android.view.accessibility.AccessibilityNodeInfo?): Boolean {
    if (node == null) return false
    if (node.text?.toString() == "Raiun is locked") return true
    return (0 until node.childCount).any { containsLockedText(node.getChild(it)) }
}
