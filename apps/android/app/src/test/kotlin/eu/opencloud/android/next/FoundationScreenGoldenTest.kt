package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performTextInput
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.auth.AuthScreen
import eu.opencloud.android.next.feature.auth.AuthUiState
import eu.opencloud.android.next.feature.auth.AuthenticationMode
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class FoundationScreenGoldenTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<ComponentActivity>()

    @Test fun basicPasswordIsMasked() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                AuthScreen(
                    AuthUiState(authenticationMode = AuthenticationMode.BASIC),
                    null,
                    { _, _ -> },
                    { _, _ -> },
                    {},
                    {},
                )
            }
        }
        composeRule.onNodeWithText("Password").performTextInput("fixture-password")
        composeRule.onNodeWithText("Password").assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Password))
    }

    @Test
    fun foundationScreen_matchesGolden() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                AuthScreen(AuthUiState(), null, { _, _ -> }, { _, _ -> }, {}, {})
            }
        }
        // Robolectric anti-aliasing may vary by a few host-rendered pixels; meaningful visual changes still fail.
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/foundation_screen.png",
            roborazziOptions =
                RoborazziOptions(
                    compareOptions =
                        RoborazziOptions.CompareOptions(
                            resultValidator = { result ->
                                result.pixelDifferences.toFloat() / result.pixelCount <= 0.001f
                            },
                        ),
                ),
        )
    }
}
