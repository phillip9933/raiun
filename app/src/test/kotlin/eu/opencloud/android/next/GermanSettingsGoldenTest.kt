package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.settings.SettingsScreen
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "de-rDE-w360dp-h800dp")
class GermanSettingsGoldenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun compactGermanSettingsRetainReadableActions() = capture(false, 1f, "settings_german")

    @Test
    @Config(qualifiers = "de-rDE-w412dp-h915dp")
    fun enlargedGermanSettingsRetainReadableActions() = capture(true, 1.3f, "settings_german_large_dark")

    private fun capture(
        dark: Boolean,
        fontScale: Float,
        name: String,
    ) {
        compose.activity.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, fontScale)) {
                OpenCloudTheme(darkTheme = dark) {
                    SettingsScreen(UserSettings(), {}, {}, {})
                }
            }
        }
        compose.onNodeWithText("Einstellungen").assertIsDisplayed()
        compose.onNodeWithText("Darstellung").assertIsDisplayed()
        compose.onRoot().captureRoboImage("src/test/snapshots/images/$name.png")
        compose.onNodeWithText("Temporäre lokale Dateien").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Darstellung").performScrollTo().performClick()
        compose.onNodeWithText("Design und Sprache").assertIsDisplayed()
        compose.onNodeWithContentDescription("Sprache ändern").assertIsDisplayed()
        compose.onRoot().captureRoboImage("src/test/snapshots/images/${name}_appearance.png")
    }
}
