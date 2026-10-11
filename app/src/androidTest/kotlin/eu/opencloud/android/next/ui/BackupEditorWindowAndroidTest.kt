package eu.opencloud.android.next.ui

import android.graphics.Bitmap
import android.view.KeyEvent
import androidx.activity.ComponentActivity
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasScrollAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import androidx.compose.ui.test.swipeUp
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.files.BackupEditorDialog
import eu.opencloud.android.next.feature.files.FolderBackupSettingsContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class BackupEditorWindowAndroidTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun newBackupScrollsWithoutMovingOrDismissingAndClosesOnSave() {
        showEditor(null)
        saveScreenshot("backup-editor-new.png")
        exerciseScrolling()
        compose.onNodeWithText("Save").performClick()
        compose.onNodeWithText("Editor closed").assertIsDisplayed()
    }

    @Test
    fun existingBackupIgnoresSwipeAndBackDismissalAndClosesOnCancel() {
        showEditor(
            FolderBackupEntity(
                id = "backup",
                accountId = "account",
                spaceId = "personal",
                sourceTreeUri = "content://test/tree/camera",
                sourceDisplayName = "Camera",
                destinationPath = "/Pictures",
                mediaType = "ALL",
                wifiOnly = true,
                chargingOnly = false,
                deleteAfterUpload = false,
            ),
        )
        saveScreenshot("backup-editor-manage.png")
        exerciseScrolling()
        compose.onNodeWithText("Cancel").performClick()
        compose.onNodeWithText("Editor closed").assertIsDisplayed()
    }

    @Test
    fun newBackupOffersDatePresets() {
        showEditor(null)
        compose.onNodeWithText("Edit").performScrollTo().performClick()
        compose.onNodeWithContentDescription("Organize files into date folders").performClick()
        compose.onNodeWithText("[YYYY]/[MM]/[DD]").performScrollTo().performClick()
        saveScreenshot("backup-date-pattern-editor.png")
        compose.onNodeWithText("Done").performClick()
        compose.onNodeWithText("[YYYY]/[MM]/[DD]").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Save").performClick()
        compose.onNodeWithText("Editor closed").assertIsDisplayed()
    }

    private fun saveScreenshot(name: String) {
        compose.waitForIdle()
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val directory =
            File(requireNotNull(InstrumentationRegistry.getArguments().getString("additionalTestOutputDir")))
        check(directory.isDirectory || directory.mkdirs())
        val screenshot = requireNotNull(instrumentation.uiAutomation.takeScreenshot())
        File(directory, name).outputStream().use { screenshot.compress(Bitmap.CompressFormat.PNG, 100, it) }
        screenshot.recycle()
    }

    private fun exerciseScrolling() {
        val saveBounds = compose.onNodeWithText("Save").fetchSemanticsNode().boundsInRoot
        repeat(5) {
            compose.onNode(hasScrollAction()).performTouchInput { swipeUp() }
            compose.onNode(hasScrollAction()).performTouchInput { swipeDown() }
        }
        InstrumentationRegistry.getInstrumentation().sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
        compose.waitForIdle()
        compose.onNodeWithText("Save").assertIsDisplayed()
        compose.onNodeWithText("Cancel").assertIsDisplayed()
        assertEquals(saveBounds, compose.onNodeWithText("Save").fetchSemanticsNode().boundsInRoot)
    }

    private fun showEditor(backup: FolderBackupEntity?) {
        compose.setContent {
            OpenCloudTheme {
                var visible by remember { mutableStateOf(true) }
                if (visible) {
                    BackupEditorDialog {
                        FolderBackupSettingsContent(
                            backups = emptyList(),
                            initialBackup = backup,
                            sourceDisplayName = "Camera",
                            onDismiss = { visible = false },
                            onAdd = { visible = false },
                            onDelete = {},
                        )
                    }
                } else {
                    Text("Editor closed")
                }
            }
        }
    }
}
