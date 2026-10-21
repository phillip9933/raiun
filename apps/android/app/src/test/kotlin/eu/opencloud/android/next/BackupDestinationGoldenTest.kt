package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.files.BackupDestination
import eu.opencloud.android.next.feature.files.BackupDestinationPickerDialog
import eu.opencloud.android.next.feature.files.BackupFolderCrumb
import eu.opencloud.android.next.feature.files.BackupSharedFolder
import eu.opencloud.android.next.feature.files.BackupSharedRoot
import eu.opencloud.android.next.feature.files.FileBrowserUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class BackupDestinationGoldenTest {
    @get:Rule val composeRule = createAndroidComposeRule<ComponentActivity>()

    @Test fun roots() {
        render(
            FileBrowserUiState(
                spaces = listOf(space("personal", "My files", "personal"), space("team", "Team photos", "project")),
                backupPickerSharedRoots = listOf(BackupSharedRoot("Family uploads", "share", "scope", "root")),
            ),
        )
        listOf("Personal", "Spaces", "Shared with me", "Family uploads").forEach {
            composeRule.onNodeWithText(it).assertIsDisplayed()
        }
        composeRule.onRoot().captureRoboImage("src/test/snapshots/rendered/backup_destination_roots.png")
    }

    @Test fun sharedSubfolder() {
        render(
            FileBrowserUiState(
                backupPickerDestination =
                    BackupDestination(
                        "scope",
                        "/Photos",
                        "SHARED_FOLDER",
                        "share",
                        "photos",
                        "Shared with me · Family uploads",
                    ),
                backupPickerTrail = listOf(BackupFolderCrumb("photos", "Photos", "/Photos")),
                backupPickerSharedFolders = listOf(BackupSharedFolder("year", "2026", "/Photos/2026")),
                backupPickerCanSelect = true,
            ),
        )
        composeRule.onNodeWithText("2026").assertIsDisplayed()
        composeRule.onRoot().captureRoboImage("src/test/snapshots/rendered/backup_destination_shared_folder.png")
    }

    private fun render(state: FileBrowserUiState) {
        composeRule.activity.setContent {
            OpenCloudTheme {
                BackupDestinationPickerDialog(state, {}, {}, {}, {}, {}, {}, {}, {}, {})
            }
        }
    }

    private fun space(
        id: String,
        name: String,
        type: String,
    ) = SpaceEntity("account", id, name, type, null, null, "root", null, null, null)
}
