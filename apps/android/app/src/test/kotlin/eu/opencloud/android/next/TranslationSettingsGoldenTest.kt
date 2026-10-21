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
import org.junit.Assert.assertNotEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35])
class TranslationSettingsGoldenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    @Config(qualifiers = "fr-w360dp-h800dp")
    fun frenchSettings() = capture("fr")

    @Test
    @Config(qualifiers = "es-w360dp-h800dp")
    fun spanishSettings() = capture("es")

    @Test
    @Config(qualifiers = "pt-rPT-w360dp-h800dp")
    fun portugueseSettings() = capture("pt-PT")

    @Test
    @Config(qualifiers = "ja-w360dp-h800dp")
    fun japaneseSettings() = capture("ja")

    @Test
    @Config(qualifiers = "pt-rPT-w412dp-h915dp")
    fun enlargedPortugueseSettings() = capture("pt-PT", 1.3f)

    private fun capture(
        tag: String,
        scale: Float = 1f,
    ) {
        val resources = compose.activity.resources
        val title = resources.getString(eu.opencloud.android.next.feature.settings.R.string.settings_title)
        val appearance = resources.getString(eu.opencloud.android.next.feature.settings.R.string.settings_appearance)
        val changeLanguage =
            resources.getString(
                eu.opencloud.android.next.feature.settings.R.string.settings_change_language,
            )
        assertNotEquals("Settings", title)
        compose.activity.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, scale)) {
                OpenCloudTheme(darkTheme = scale > 1f) {
                    SettingsScreen(UserSettings(), {}, {}, {}, languageTag = tag)
                }
            }
        }
        compose.onNodeWithText(title).assertIsDisplayed()
        compose.onNodeWithText(appearance).assertIsDisplayed()
        val name = "settings_${tag}_$scale"
        compose.onRoot().captureRoboImage("src/test/snapshots/images/$name.png")
        compose.onNodeWithText(appearance).performScrollTo().performClick()
        compose.onNodeWithContentDescription(changeLanguage).assertIsDisplayed()
        compose.onRoot().captureRoboImage("src/test/snapshots/images/${name}_appearance.png")
    }
}
