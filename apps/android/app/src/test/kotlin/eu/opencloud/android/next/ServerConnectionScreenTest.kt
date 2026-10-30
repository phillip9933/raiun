package eu.opencloud.android.next

import android.app.Application
import androidx.activity.ComponentActivity
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
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
        compose.onNodeWithText("Wi-Fi & certificates").assertIsDisplayed()
        // Diagnostic render in build output, separate from the verified screenshot baselines.
        compose.onRoot().captureRoboImage(
            "build/reports/server-connection-api${android.os.Build.VERSION.SDK_INT}.png",
            roborazziOptions = RoborazziOptions(taskType = RoborazziTaskType.Record),
        )
        compose.onNodeWithText("Cancel").assertIsDisplayed().performClick()
        assertTrue(closed)
        assertNull(WifiServerRouteStore(context).find(server))
    }

    @Test fun connectionSettingsExplainTheClientCertificateBoundary() {
        compose.setContent {
            OpenCloudTheme { ServerConnectionScreen("https://certificate-connection.example", {}) }
        }
        compose.onNodeWithText("Sign-in certificate").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Configure").performScrollTo().performClick()
        compose.onNodeWithText("Choose certificate").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Allowed HTTPS sites (one per line)").performScrollTo().assertIsDisplayed()
        compose.onNodeWithContentDescription("About sign-in certificates").performScrollTo().performClick()
        compose
            .onNodeWithText(
                "The Android certificate picker grants Raiun access to the key. The separate browser used for sign-in has its own certificate access. OAuth certificate-bound tokens are not supported.",
            ).assertIsDisplayed()
    }

    @Test fun expandingCertificateOptionsPreservesDraftWithoutSaving() {
        val server = "https://draft-connection.example"
        compose.setContent { OpenCloudTheme { ServerConnectionScreen(server, {}) } }
        compose.onNodeWithText("Allowed HTTPS sites (one per line)").assertDoesNotExist()
        compose.onNodeWithText("Configure").performScrollTo().performClick()
        compose
            .onNodeWithText("Allowed HTTPS sites (one per line)")
            .performScrollTo()
            .performTextInput("https://login.example.org")
        compose.onNodeWithText("Hide options").performScrollTo().performClick()
        compose.onNodeWithText("Allowed HTTPS sites (one per line)").assertDoesNotExist()
        compose.onNodeWithText("Configure").performScrollTo().performClick()
        compose.onNodeWithText("https://login.example.org").performScrollTo().assertIsDisplayed()
        val context = ApplicationProvider.getApplicationContext<Application>()
        assertNull(WifiServerRouteStore(context).find(server))
        assertNull(
            eu.opencloud.android.next.core.security
                .ClientCertificatePolicy(context)
                .load(server),
        )
    }

    @Test fun wifiFieldsAreOptionalAndCancelKeepsSavedSettings() {
        val context = ApplicationProvider.getApplicationContext<Application>()
        val server = "https://wifi-draft.example"
        compose.setContent { OpenCloudTheme(darkTheme = true) { ServerConnectionScreen(server, {}) } }
        compose.onNodeWithText("Local server address (HTTPS)").assertDoesNotExist()
        compose.waitUntil(5_000) {
            !compose
                .onNodeWithContentDescription("Use local access on Wi-Fi")
                .fetchSemanticsNode()
                .config
                .contains(SemanticsProperties.Disabled)
        }
        compose.onNodeWithContentDescription("Use local access on Wi-Fi").performClick()
        compose
            .onNodeWithText("Local server address (HTTPS)")
            .performScrollTo()
            .performTextInput("https://192.0.2.20")
        compose.onNodeWithText("Cancel").assertIsDisplayed().performClick()
        assertNull(WifiServerRouteStore(context).find(server))
    }
}
