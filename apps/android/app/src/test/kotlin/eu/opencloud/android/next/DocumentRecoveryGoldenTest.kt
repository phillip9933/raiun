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
import eu.opencloud.android.next.core.sync.DocumentEdit
import eu.opencloud.android.next.core.sync.DocumentEditInventory
import eu.opencloud.android.next.core.sync.DocumentEditState
import eu.opencloud.android.next.feature.transfers.DocumentEditsContent
import eu.opencloud.android.next.feature.transfers.DocumentEditsState
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
class DocumentRecoveryGoldenTest {
    @get:Rule val composeRule = createAndroidComposeRule<ComponentActivity>()
    private val edit =
        DocumentEdit(
            "edit",
            "account",
            "space",
            "resource",
            "/Documents/Notes.txt",
            "Notes.txt",
            "text/plain",
            "\"v1\"",
        )

    @Test fun reviewExplainsRecoveryAndRequiresDiscardConfirmation() {
        var discarded = 0
        var exported = 0
        composeRule.activity.setContent {
            OpenCloudTheme {
                DocumentEditsContent(
                    DocumentEditsState(DocumentEditInventory(listOf(edit), unreadableCount = 1)),
                    { exported++ },
                    { discarded++ },
                    {},
                    {},
                )
            }
        }
        composeRule.onRoot().captureRoboImage("src/test/snapshots/images/document_recovery.png")
        composeRule.onNodeWithText("Export copy").performClick()
        assertEquals(1, exported)
        composeRule.onNodeWithText("Discard").performClick()
        assertEquals(0, discarded)
        composeRule.onNodeWithText("Cancel").performClick()
        assertEquals(0, discarded)
        composeRule.onNodeWithText("Discard").performClick()
        composeRule.onNodeWithText("Discard edit").performClick()
        assertEquals(1, discarded)
    }

    @Test fun activeEditorDisablesRecoveryActions() {
        composeRule.activity.setContent {
            OpenCloudTheme(darkTheme = true) {
                DocumentEditsContent(
                    DocumentEditsState(DocumentEditInventory(listOf(edit)), activeIds = setOf(edit.id)),
                    {},
                    {},
                    {},
                    {},
                )
            }
        }
        composeRule.onNodeWithText("Export copy").assertIsNotEnabled()
        composeRule.onNodeWithText("Discard").assertIsNotEnabled()
        composeRule.onRoot().captureRoboImage("src/test/snapshots/images/document_recovery_active_dark.png")
    }

    @Test fun queuedSaveCannotBeDiscarded() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                DocumentEditsContent(
                    DocumentEditsState(DocumentEditInventory(listOf(edit.copy(state = DocumentEditState.SUBMITTED)))),
                    {},
                    {},
                    {},
                    {},
                )
            }
        }
        composeRule.onNodeWithText("Discard").assertDoesNotExist()
    }
}
