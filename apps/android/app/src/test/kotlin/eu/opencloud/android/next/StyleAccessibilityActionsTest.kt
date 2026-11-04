package eu.opencloud.android.next

import android.app.Application
import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.ComponentActivity
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsToggleable
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.ui.FolderIconCropDialog
import eu.opencloud.android.next.feature.settings.AppUpdatesScreen
import eu.opencloud.android.next.feature.settings.SettingsScreen
import eu.opencloud.android.next.feature.settings.UpdateActions
import io.github.phillip9933.appupdater.AndroidUpdateChannel
import io.github.phillip9933.appupdater.UpdateState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w320dp-h640dp", application = Application::class)
class StyleAccessibilityActionsTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun photoLocationPurposeAndToggleAreOneAction() {
        compose.activity
            .getSharedPreferences("photo_metadata_preferences", 0)
            .edit()
            .clear()
            .commit()
        compose.setContent { OpenCloudTheme { SettingsScreen(UserSettings(), {}, {}, {}) } }
        compose.onNodeWithText("Permissions").performScrollTo().performClick()
        val row = compose.onNodeWithText("Ask to preserve photo location")
        row.performScrollTo().assertIsToggleable()
        val before = row.fetchSemanticsNode().config[androidx.compose.ui.semantics.SemanticsProperties.ToggleableState]
        row.performClick()
        compose.waitForIdle()
        val after = row.fetchSemanticsNode().config[androidx.compose.ui.semantics.SemanticsProperties.ToggleableState]
        assertTrue(before != after)
    }

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

    @Test fun cropAccessibilityActionsPanBothAxesAndClampAtEdges() {
        val source = Bitmap.createBitmap(80, 80, Bitmap.Config.ARGB_8888)
        for (x in 0 until 80) for (y in 0 until 80) source.setPixel(x, y, Color.rgb(x, y, 0))
        var applied: Bitmap? = null
        compose.setContent { OpenCloudTheme { FolderIconCropDialog(source, {}, { applied = it }) } }

        fun action(label: String) {
            val actions =
                compose
                    .onNodeWithContentDescription("Shortcut icon preview")
                    .fetchSemanticsNode()
                    .config[SemanticsActions.CustomActions]
            compose.runOnIdle { assertTrue(actions.single { it.label == label }.action()) }
        }
        action("Zoom in")
        repeat(10) {
            action("Move image left")
            action("Move image up")
        }
        compose.onNodeWithText("Use image").performClick()
        assertEquals(source.getPixel(16, 16), requireNotNull(applied).getPixel(0, 0))
        repeat(10) {
            action("Move image right")
            action("Move image down")
        }
        compose.onNodeWithText("Use image").performClick()
        assertEquals(source.getPixel(0, 0), requireNotNull(applied).getPixel(0, 0))
    }
}
