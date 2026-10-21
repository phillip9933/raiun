package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.feature.files.ScannerDestinationActions
import eu.opencloud.android.next.feature.files.ScannerDestinationPickerState
import eu.opencloud.android.next.feature.files.ScannerDestinationScreen
import eu.opencloud.android.next.feature.files.ScannerLocationButton
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
class ScannerLocationGoldenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun nestedSpaceLocationIsAButtonAndReflectsSelection() {
        compose.setContent {
            var label by remember { mutableStateOf("Team research / Projects/Notes") }
            OpenCloudTheme {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.padding(OpenCloudDimensions.SpacingMd)) {
                        ScannerLocationButton(label, true, { label = "Personal /" })
                    }
                }
            }
        }
        compose.onNodeWithText("Team research / Projects/Notes").assertIsEnabled()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/scanner_location_button.png")
        compose.onNodeWithText("Team research / Projects/Notes").performClick()
        compose.onNodeWithText("Personal /").assertExists()
    }

    @Test fun destinationCannotChangeDuringExport() {
        compose.setContent {
            OpenCloudTheme { ScannerLocationButton("Personal /", false, {}) }
        }
        compose.onNodeWithText("Personal /").assertIsNotEnabled()
    }

    @Test fun destinationHierarchyAndChangeAreClear() {
        var changed = false
        var chosen = false
        val folder =
            ResourceEntity(
                "account",
                "team",
                "notes",
                null,
                "/Notes",
                "Notes",
                ResourceKind.FOLDER,
                null,
                0,
                null,
                0,
                0,
            )
        val space = SpaceEntity("account", "team", "Team research", "project", null, null, "root", null, null, null)
        compose.setContent {
            OpenCloudTheme {
                ScannerDestinationScreen(
                    ScannerDestinationPickerState(
                        accountLabel = "Alex Example · cloud.example",
                        spaces = listOf(space),
                        spaceId = "team",
                        path = "/Notes",
                        trail = listOf(folder),
                        folders = listOf(folder.copy(name = "Receipts", remoteId = "receipts")),
                        busy = false,
                        validFolder = true,
                    ),
                    ScannerDestinationActions({}, { chosen = true }, { changed = true }, {}, {}, {}, {}, {}),
                )
            }
        }
        compose.onNodeWithText("Save in this folder").assertIsEnabled()
        compose.onNodeWithText("Alex Example · cloud.example").assertExists()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/scanner_destination_folder.png")
        compose.onNodeWithText("Change").performClick()
        assertEquals(true, changed)
        compose.onNodeWithText("Save in this folder").performClick()
        assertEquals(true, chosen)
    }

    @Test fun spaceSelectionDoesNotEnableSaveUntilFolderSelected() {
        val personal =
            SpaceEntity("account", "personal", "Phil Rogers", "personal", null, null, "root", null, null, null)
        var selected = ""
        compose.setContent {
            OpenCloudTheme(darkTheme = true) {
                ScannerDestinationScreen(
                    ScannerDestinationPickerState(
                        accountLabel = "Alex Example · cloud.example",
                        spaces =
                            listOf(
                                personal,
                                personal.copy(driveId = "team", name = "Team research", type = "project"),
                            ),
                        busy = false,
                    ),
                    ScannerDestinationActions({}, {}, {}, { selected = it }, {}, {}, {}, {}),
                )
            }
        }
        compose.onNodeWithText("Save in this folder").assertIsNotEnabled()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/scanner_destination_spaces_dark.png")
        compose.onNodeWithText("Personal").performClick()
        assertEquals("personal", selected)
    }
}
