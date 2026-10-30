package eu.opencloud.android.next

import android.app.KeyguardManager
import android.graphics.Bitmap
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import eu.opencloud.android.next.core.security.AppLock
import java.io.File

/** Bounded state only: no accessibility text, intent data, server addresses or exception messages. */
internal class NativeUiDiagnostics(
    private val name: String,
) {
    private val stages = ArrayDeque<String>()

    fun stage(value: String) {
        if (stages.size == 32) stages.removeFirst()
        stages.addLast(value)
    }

    /** Wake only; secure credentials remain entirely under the device owner's control. */
    fun prepareDevice() {
        stage("before-prepare-device")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val power = context.getSystemService(PowerManager::class.java)
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        shell("input keyevent KEYCODE_WAKEUP")
        awaitCondition("UI tests require an interactive display after KEYCODE_WAKEUP") { power.isInteractive }
        check(!keyguard.isDeviceSecure || !keyguard.isDeviceLocked) {
            "Unlock the secure test device manually before running native UI tests; credentials are never bypassed."
        }
        if (!keyguard.isDeviceSecure) {
            shell("wm dismiss-keyguard")
            awaitCondition("Dismiss the unsecured test device keyguard before running native UI tests") {
                !keyguard.isKeyguardLocked
            }
        }
        stage("after-prepare-device")
    }

    /** A Compose dialog may own focus even when the hosting Activity does not. */
    fun awaitAppWindow() {
        stage("before-await-app-window")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val expected = instrumentation.targetContext.packageName
        awaitCondition("Native input requires the target application's active accessibility window") {
            instrumentation.uiAutomation.rootInActiveWindow
                ?.packageName
                ?.toString() == expected
        }
        stage("after-await-app-window")
    }

    private fun awaitCondition(
        message: String,
        condition: () -> Boolean,
    ) {
        val deadline = SystemClock.uptimeMillis() + 5_000
        while (!condition()) {
            check(SystemClock.uptimeMillis() < deadline) { message }
            SystemClock.sleep(50)
        }
    }

    private fun shell(command: String) {
        val descriptor = InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand(command)
        ParcelFileDescriptor.AutoCloseInputStream(descriptor).use { it.readBytes() }
    }

    fun failure(error: Throwable) {
        // Diagnostic failures must never replace the original assertion or input failure.
        runCatching {
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val context = instrumentation.targetContext
            val directory =
                File(requireNotNull(InstrumentationRegistry.getArguments().getString("additionalTestOutputDir")))
            check(directory.isDirectory || directory.mkdirs())
            val lock = AppLock(context)
            val keyguard = context.getSystemService(KeyguardManager::class.java)
            val state = StringBuilder()
            state.appendLine("api=${Build.VERSION.SDK_INT}")
            state.appendLine("exception=${error.javaClass.name}")
            stages.forEach { state.appendLine("stage=$it") }
            state.appendLine("lock.enabled=${lock.enabled}")
            state.appendLine("lock.deviceSecure=${lock.deviceSecure}")
            state.appendLine("lock.canOpenApp=${lock.canOpenApp()}")
            state.appendLine("lock.canOpenDocuments=${lock.canOpenDocuments()}")
            state.appendLine("keyguard.locked=${keyguard.isKeyguardLocked}")
            state.appendLine("keyguard.deviceLocked=${keyguard.isDeviceLocked}")
            state.appendLine("power.interactive=${context.getSystemService(PowerManager::class.java).isInteractive}")
            instrumentation.runOnMainSync {
                val monitor = ActivityLifecycleMonitorRegistry.getInstance()
                listOf(Stage.RESUMED, Stage.STARTED, Stage.PAUSED, Stage.STOPPED).forEach { lifecycle ->
                    monitor.getActivitiesInStage(lifecycle).take(8).forEach { activity ->
                        state.appendLine("activity=$lifecycle:${activity.javaClass.name}")
                        state.appendLine("window.focused=${activity.hasWindowFocus()}")
                        state.appendLine("window.flags=${activity.window.attributes.flags}")
                        state.appendLine("activity.finishing=${activity.isFinishing}")
                    }
                }
            }
            val root = instrumentation.uiAutomation.rootInActiveWindow
            state.appendLine("accessibility.package=${root?.packageName}")
            state.appendLine("accessibility.windowId=${root?.windowId}")
            File(directory, "$name-diagnostics.txt").writeText(state.toString())
            runCatching {
                val screenshot = instrumentation.uiAutomation.takeScreenshot()
                if (screenshot != null) {
                    try {
                        File(directory, "$name-failure.png").outputStream().use {
                            screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)
                        }
                    } finally {
                        screenshot.recycle()
                    }
                }
            }
        }
    }
}
