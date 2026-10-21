package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.network.ItemActivity
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.ui.ItemActivitiesDialog
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class ItemActivitiesTest {
    @get:Rule val timeZone = GoldenTimeZoneRule("UTC")

    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun showsActivityAndReturnsToDetails() {
        var back = 0
        compose.setContent {
            OpenCloudTheme {
                ItemActivitiesDialog("Notes.txt", { back++ }) {
                    listOf(ItemActivity("one", "Alex updated Notes.txt", "2026-10-03T12:00:00Z"))
                }
            }
        }
        compose.onNodeWithText("Alex updated Notes.txt").assertIsDisplayed()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/item_activities.png")
        compose.onNodeWithText("Back to details").performClick()
        assertEquals(1, back)
    }

    @Test fun retryReplacesFailureWithEmptyState() {
        var calls = 0
        compose.setContent {
            OpenCloudTheme {
                ItemActivitiesDialog("Folder", {}) {
                    calls++
                    if (calls == 1) throw TransferHttpException(503)
                    emptyList()
                }
            }
        }
        compose
            .onNodeWithText(
                "Could not load activities. Check your connection and access, then retry.",
            ).assertIsDisplayed()
        compose.onNodeWithText("Retry").performClick()
        compose.onNodeWithText("No activities").assertIsDisplayed()
        compose.onNodeWithText("Refresh").performClick()
        compose.waitForIdle()
        assertEquals(3, calls)
    }

    @Test fun unsupportedServerIsNotShownAsAnEmptyHistory() {
        compose.setContent {
            OpenCloudTheme { ItemActivitiesDialog("Folder", {}) { throw TransferHttpException(404) } }
        }
        compose.onNodeWithText("Activities are not available on this server or for this item.").assertIsDisplayed()
        compose.onNodeWithText("No activities").assertDoesNotExist()
    }
}
