package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.files.FolderBackupSettingsContent
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class BackupEditorGoldenTest {
    @get:Rule val composeRule = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun backupEditorMainForm_matchesGolden() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    FolderBackupSettingsContent(
                        backups = emptyList(),
                        sourceDisplayName = "Camera",
                        onDismiss = {},
                        onAdd = {},
                        onDelete = {},
                    )
                }
            }
        }
        composeRule.onNodeWithText("Source folder on this device").assertIsDisplayed()
        composeRule.onNodeWithText("Destination folder in the cloud").assertIsDisplayed()
        composeRule.onNodeWithText("Save").assertIsDisplayed()
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/backup_editor_main.png",
            roborazziOptions = browserRoborazziOptions(),
        )
    }

    @Test
    fun backupEditorMainFormDark_matchesGolden() {
        composeRule.activity.setContent {
            OpenCloudTheme(darkTheme = true) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    FolderBackupSettingsContent(
                        backups = emptyList(),
                        sourceDisplayName = "Camera",
                        onDismiss = {},
                        onAdd = {},
                        onDelete = {},
                    )
                }
            }
        }
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/backup_editor_main_dark.png",
            roborazziOptions = browserRoborazziOptions(),
        )
    }

    private fun browserRoborazziOptions() = RoborazziOptions()
}
