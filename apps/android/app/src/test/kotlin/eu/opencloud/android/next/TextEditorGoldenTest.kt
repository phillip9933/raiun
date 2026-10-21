package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.sync.TextDraft
import eu.opencloud.android.next.feature.files.TextEditorScreen
import eu.opencloud.android.next.feature.files.TextEditorState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class TextEditorGoldenTest {
    @get:Rule val composeRule = createAndroidComposeRule<ComponentActivity>()
    private val draft =
        TextDraft(
            "account",
            "space",
            "notes",
            "/Notes.txt",
            "Notes.txt",
            "text/plain",
            "\"v1\"",
            "Meeting notes\n\nKeep the original photos.\nReview the upload history.\n",
        )

    @Test fun editableDraft_matchesGoldenAndSavesOnlyWhenRequested() {
        var saves = 0
        composeRule.activity.setContent {
            OpenCloudTheme {
                TextEditorScreen(TextEditorState(draft, busy = false), {}, { saves++ }, {}, {})
            }
        }
        assertEquals(0, saves)
        composeRule.onNodeWithText("Save to server").performClick()
        assertEquals(1, saves)
        composeRule.onRoot().captureRoboImage("src/test/snapshots/images/text_editor.png")
    }

    @Test fun queuedDraft_disablesDuplicateSubmission() {
        composeRule.activity.setContent {
            OpenCloudTheme(darkTheme = true) {
                TextEditorScreen(TextEditorState(draft.copy(queuedId = "upload"), busy = false), {}, {}, {}, {})
            }
        }
        composeRule.onNodeWithText("Save to server").assertIsNotEnabled()
        composeRule.onNodeWithText("Discard draft").assertDoesNotExist()
        composeRule.onRoot().captureRoboImage("src/test/snapshots/images/text_editor_queued_dark.png")
    }

    @Test fun discardRequiresConfirmation() {
        var discarded = 0
        composeRule.activity.setContent {
            OpenCloudTheme {
                TextEditorScreen(TextEditorState(draft, busy = false), {}, {}, {}, {}, onDiscard = { discarded++ })
            }
        }
        composeRule.onNodeWithText("Discard draft").performClick()
        assertEquals(0, discarded)
        composeRule.onNodeWithText("Cancel").performClick()
        assertEquals(0, discarded)
        composeRule.onNodeWithText("Discard draft").performClick()
        composeRule.onNodeWithText("Discard").performClick()
        assertEquals(1, discarded)
    }
}
