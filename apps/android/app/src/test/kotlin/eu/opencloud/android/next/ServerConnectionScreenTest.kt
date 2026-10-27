package eu.opencloud.android.next

import android.app.Application
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.core.app.ApplicationProvider
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.RoborazziTaskType
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.security.WifiServerRouteStore
import eu.opencloud.android.next.feature.settings.ServerConnectionScreen
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [26, 35], qualifiers = "w360dp-h800dp", application = Application::class)
class ServerConnectionScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @OptIn(com.github.takahirom.roborazzi.ExperimentalRoborazziApi::class)
    @Test
    fun cancellationDoesNotEnableRoutingOrWriteAnIdentity() {
        val context = ApplicationProvider.getApplicationContext<Application>()
        val server = "https://cancel-connection.example"
        var closed = false
        compose.setContent { OpenCloudTheme { ServerConnectionScreen(server) { closed = true } } }
        compose.onNodeWithText("Server connection").assertIsDisplayed()
        // Diagnostic render in build output, separate from the verified screenshot baselines.
        compose.onRoot().captureRoboImage(
            "build/reports/server-connection-api${android.os.Build.VERSION.SDK_INT}.png",
            roborazziOptions = RoborazziOptions(taskType = RoborazziTaskType.Record),
        )
        compose.onNodeWithText("Cancel").performScrollTo().performClick()
        assertTrue(closed)
        assertNull(WifiServerRouteStore(context).find(server))
    }

    @Test fun connectionSettingsExplainTheClientCertificateBoundary() {
        compose.setContent {
            OpenCloudTheme { ServerConnectionScreen("https://certificate-connection.example", {}) }
        }
        compose.onNodeWithText("TLS client certificate").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Select certificate").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("HTTPS origins (one per line)").performScrollTo().assertIsDisplayed()
    }
}
