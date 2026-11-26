package eu.opencloud.android.next

import android.app.Application
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.settings.AppUpdatesScreen
import eu.opencloud.android.next.feature.settings.UpdateActions
import io.github.phillip9933.appupdater.AndroidUpdateChannel
import io.github.phillip9933.appupdater.UpdateState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w320dp-h640dp", application = Application::class)
class UpdaterAccessibilityActionsTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun updaterLinksAndChannelsRemainReachableAtDoubleFontSize() {
        val opened = mutableListOf<String>()
        var channel: AndroidUpdateChannel? = null
        compose.setContent {
            CompositionLocalProvider(LocalDensity provides Density(LocalDensity.current.density, 2f)) {
                OpenCloudTheme {
                    AppUpdatesScreen(
                        UpdateState(installedVersion = "1.2.0"),
                        {},
                        UpdateActions(onOpenLink = { opened.add(it) }, onChannel = { channel = it }),
                    )
                }
            }
        }
        listOf("GitHub project", "Installed release").forEach {
            compose
                .onNodeWithText(it)
                .performScrollTo()
                .assertIsDisplayed()
                .performClick()
        }
        assertEquals(2, opened.size)
        compose
            .onNodeWithText("Stable and beta")
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        assertEquals(AndroidUpdateChannel.BETA, channel)
        compose
            .onNodeWithText("Stable")
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        assertEquals(AndroidUpdateChannel.STABLE, channel)
    }
}
