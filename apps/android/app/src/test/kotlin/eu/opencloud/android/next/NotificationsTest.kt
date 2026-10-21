package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.network.ServerNotification
import eu.opencloud.android.next.feature.files.NotificationInbox
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
class NotificationsTest {
    @get:Rule val timeZoneRule = GoldenTimeZoneRule("Asia/Tokyo")

    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val messages =
        listOf(
            ServerNotification(
                "42",
                "New share",
                "ChatGPT Test shared Raiun Testing with you.",
                "2026-10-03T12:00:00Z",
                true,
            ),
        )

    @Test fun inboxOpensSharesAndOnlyMarksReadOnExplicitAction() {
        var opened = 0
        var read = emptyList<String>()
        compose.setContent {
            OpenCloudTheme {
                NotificationInbox(messages, false, null, {}, {}, { read = it }, { opened++ })
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/notifications.png")
        compose.onNodeWithText("Shared with me").performClick()
        assertEquals(1, opened)
        assertEquals(emptyList<String>(), read)
        compose.onNodeWithText("Mark read").performClick()
        assertEquals(listOf("42"), read)
        compose.onNodeWithText("Mark all read").performClick()
        assertEquals(listOf("42"), read)
    }

    @Test fun failedRefreshKeepsMessagesAndNeverClaimsInboxIsEmpty() {
        compose.setContent {
            OpenCloudTheme {
                NotificationInbox(messages, false, "Unable to refresh notifications.", {}, {}, {}, {})
            }
        }
        compose.onAllNodesWithText("New share").assertCountEquals(1)
        compose.onAllNodesWithText("No new notifications").assertCountEquals(0)
    }

    @Test fun pendingRequestPreventsDuplicateMarkRead() {
        compose.setContent { OpenCloudTheme { NotificationInbox(messages, true, null, {}, {}, {}, {}) } }
        compose.onNodeWithText("Mark read").assertIsNotEnabled()
        compose.onNodeWithText("Mark all read").assertIsNotEnabled()
    }
}
