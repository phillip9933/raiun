package eu.opencloud.android.next

import android.app.Application
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.UriHandler
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.settings.SettingsScreen
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import eu.opencloud.android.next.feature.settings.R as SettingsR

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp", application = Application::class)
class PlayPrivacyPolicyTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun browserFailureIsVisibleAndClearsWhenRetryWorks() {
        var browserAvailable = false
        var openedUrl: String? = null
        val browser =
            object : UriHandler {
                override fun openUri(uri: String) {
                    require(browserAvailable) { "No browser installed" }
                    openedUrl = uri
                }
            }
        compose.setContent {
            CompositionLocalProvider(LocalUriHandler provides browser) {
                OpenCloudTheme {
                    SettingsScreen(UserSettings(), {}, {}, {}, openUpdatesInitially = true)
                }
            }
        }
        val privacy = compose.onNodeWithText(compose.activity.getString(SettingsR.string.play_privacy_policy))
        val error = compose.onNodeWithText(compose.activity.getString(SettingsR.string.play_privacy_policy_open_failed))
        compose.onNodeWithText(compose.activity.getString(SettingsR.string.updates_title)).assertDoesNotExist()
        error.assertDoesNotExist()
        privacy.performScrollTo().performClick()
        error.performScrollTo().assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(null, openedUrl)
            browserAvailable = true
        }
        privacy.performScrollTo().performClick()
        error.assertDoesNotExist()
        compose.runOnIdle {
            assertEquals("https://github.com/phillip9933/raiun/blob/main/apps/android/PRIVACY.md", openedUrl)
        }
    }
}
