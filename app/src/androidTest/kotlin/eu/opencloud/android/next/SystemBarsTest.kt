package eu.opencloud.android.next

import android.content.Intent
import android.graphics.Bitmap
import android.os.SystemClock
import androidx.core.view.WindowCompat
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.datastore.Appearance
import eu.opencloud.android.next.core.datastore.SettingsRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

@SdkSuppress(minSdkVersion = 29)
class SystemBarsTest {
    @Test fun explicitDarkModeControlsSystemBars() =
        runBlocking {
            org.junit.Assume.assumeTrue(android.os.Build.VERSION.SDK_INT >= 29)
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val context = instrumentation.targetContext
            val settings = SettingsRepository.create(context)
            val previous = settings.settings.first().appearance
            var activity: MainActivity? = null
            try {
                settings.setAppearance(Appearance.DARK)
                val target =
                    instrumentation.startActivitySync(
                        Intent(context, MainActivity::class.java)
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK),
                    ) as MainActivity
                activity = target
                var dark = false
                val deadline = SystemClock.uptimeMillis() + 5_000
                while (!dark && SystemClock.uptimeMillis() < deadline) {
                    instrumentation.runOnMainSync {
                        val window = target.window
                        dark =
                            !WindowCompat
                                .getInsetsController(
                                    window,
                                    window.decorView,
                                ).isAppearanceLightNavigationBars &&
                            !window.isNavigationBarContrastEnforced
                    }
                    SystemClock.sleep(50)
                }
                assertTrue("Dark mode must use light buttons without the platform light scrim", dark)
                instrumentation.waitForIdleSync()
                SystemClock.sleep(250)
                val bitmap = requireNotNull(instrumentation.uiAutomation.takeScreenshot())
                File(context.getExternalFilesDir(null), "system-bars-dark.png").outputStream().use {
                    bitmap.compress(Bitmap.CompressFormat.PNG, 100, it)
                }
                bitmap.recycle()
            } finally {
                instrumentation.runOnMainSync { activity?.finish() }
                settings.setAppearance(previous)
            }
        }
}
