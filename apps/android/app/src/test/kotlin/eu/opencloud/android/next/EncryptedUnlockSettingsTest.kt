package eu.opencloud.android.next

import android.app.Application
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsOff
import androidx.compose.ui.test.assertIsOn
import androidx.compose.ui.test.assertIsToggleable
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.security.VaultUnlockPolicy
import eu.opencloud.android.next.feature.settings.SettingsScreen
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [26, 35], qualifiers = "w320dp-h640dp", application = Application::class)
class EncryptedUnlockSettingsTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @After fun resetFixturePolicy() {
        VaultUnlockPolicy(compose.activity).setAskEveryTime(false)
    }

    @Test fun labelledAskEveryTimeChoicePersistsAcrossSettingsVisits() {
        val policy = VaultUnlockPolicy(compose.activity)
        policy.setAskEveryTime(false)
        compose.setContent { OpenCloudTheme { SettingsScreen(UserSettings(), {}, {}, {}) } }
        compose.onNodeWithText("Encrypted preferences").performScrollTo().performClick()
        val choice = compose.onNodeWithText("Ask every time")
        choice.performScrollTo().assertIsToggleable().assertIsOff()
        choice.performClick()
        choice.assertIsOn()
        assertTrue(VaultUnlockPolicy(compose.activity).askEveryTime())
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Encrypted preferences").performScrollTo().performClick()
        compose.onNodeWithText("Ask every time").performScrollTo().assertIsOn()
    }
}
