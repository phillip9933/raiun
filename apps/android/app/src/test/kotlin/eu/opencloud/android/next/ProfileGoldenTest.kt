package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Surface
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.designsystem.RaiunWordmark
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.network.ServerAccountProfile
import eu.opencloud.android.next.feature.account.AccountDetailsScreen
import eu.opencloud.android.next.feature.account.AccountDetailsState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class ProfileGoldenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun accountInformationLight() = capture(false)

    @Test fun accountInformationDark() = capture(true)

    @Test fun raiunBrandingBothThemes() {
        compose.setContent {
            Column {
                OpenCloudTheme(darkTheme = false) { Surface { RaiunWordmark() } }
                OpenCloudTheme(darkTheme = true) { Surface { RaiunWordmark() } }
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/raiun_branding.png")
    }

    private fun capture(dark: Boolean) {
        compose.setContent {
            OpenCloudTheme(darkTheme = dark) {
                AccountDetailsScreen(
                    AccountEntity("profile", "https://cloud.example.test", "phil", "Phil Rogers", "OIDC", false),
                    AccountDetailsState(
                        profile =
                            ServerAccountProfile(
                                "phil",
                                "Phil Rogers",
                                "phil@example.test",
                                listOf("team", "editors"),
                                350000000,
                                1000000000,
                            ),
                    ),
                    onNavigateBack = {},
                    onUpload = {},
                    onRemovePhoto = {},
                    onRefresh = {},
                )
            }
        }
        compose.onRoot().captureRoboImage(
            "src/test/snapshots/rendered/account_information_${if (dark) "dark" else "light"}.png",
        )
    }
}
