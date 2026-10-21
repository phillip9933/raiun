package eu.opencloud.android.next

import android.app.KeyguardManager
import androidx.activity.ComponentActivity
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.security.AppLock
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class DeviceLockGateTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun lockingHidesContentAndRestoresSavedUiAfterAuthentication() {
        val lock = AppLock(compose.activity)
        Shadows.shadowOf(compose.activity.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        lock.authenticated()
        lock.setEnabled(true)
        try {
            compose.setContent {
                OpenCloudTheme(darkTheme = true) {
                    DeviceLockGate(compose.activity) {
                        var counter by rememberSaveable { mutableIntStateOf(0) }
                        Button(onClick = { counter++ }) { Text("Private screen $counter") }
                    }
                }
            }
            compose.onNodeWithText("Private screen 0").performClick()
            compose.runOnIdle {
                lock.background()
                lock.preferences
                    .edit()
                    .putBoolean("test-refresh", true)
                    .commit()
            }
            compose.onNodeWithText("Private screen 1").assertDoesNotExist()
            compose.onNodeWithText("Raiun is locked").assertIsDisplayed()
            val prompt = Shadows.shadowOf(compose.activity).nextStartedActivityForResult
            org.junit.Assert.assertEquals(DeviceUnlockActivity::class.java.name, prompt.intent.component?.className)
            compose.runOnIdle {
                compose.activity.activityResultRegistry.dispatchResult(
                    prompt.requestCode,
                    android.app.Activity.RESULT_CANCELED,
                    null,
                )
            }
            compose.waitForIdle()
            org.junit.Assert.assertNull(Shadows.shadowOf(compose.activity).nextStartedActivityForResult)
            compose.onNodeWithText("Raiun is locked").assertIsDisplayed()
            compose.activityRule.scenario.moveToState(androidx.lifecycle.Lifecycle.State.CREATED)
            compose.activityRule.scenario.moveToState(androidx.lifecycle.Lifecycle.State.RESUMED)
            compose.waitForIdle()
            val nextPrompt = Shadows.shadowOf(compose.activity).nextStartedActivityForResult
            org.junit.Assert.assertEquals(DeviceUnlockActivity::class.java.name, nextPrompt.intent.component?.className)
            compose.runOnIdle {
                compose.activity.activityResultRegistry.dispatchResult(
                    nextPrompt.requestCode,
                    android.app.Activity.RESULT_CANCELED,
                    null,
                )
            }
            compose.onRoot().captureRoboImage("src/test/snapshots/rendered/app_locked_dark.png")
            compose.runOnIdle {
                lock.authenticated()
                lock.preferences
                    .edit()
                    .putBoolean("test-refresh", false)
                    .commit()
            }
            compose.onNodeWithText("Private screen 1").assertIsDisplayed()
        } finally {
            lock.preferences
                .edit()
                .clear()
                .commit()
            lock.lock()
        }
    }
}
