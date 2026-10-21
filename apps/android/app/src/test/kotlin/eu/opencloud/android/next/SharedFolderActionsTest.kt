package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.network.SharedFolderAccess
import eu.opencloud.android.next.core.sync.IncomingFolderDetails
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import eu.opencloud.android.next.feature.shares.IncomingBrowserItem
import eu.opencloud.android.next.feature.shares.IncomingBrowserScreen
import eu.opencloud.android.next.feature.shares.IncomingBrowserState
import eu.opencloud.android.next.feature.shares.IncomingFolderActionSheet
import eu.opencloud.android.next.feature.shares.IncomingFolderDetailsDialog
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
class SharedFolderActionsTest {
    @get:Rule val timeZoneRule = GoldenTimeZoneRule("Asia/Tokyo")

    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private val folder =
        IncomingBrowserItem.Folder(
            "Raiun Testing",
            SharedFolderRequest("a", "s", "scope", "root", "/"),
        )
    private val details =
        IncomingFolderDetails(
            "Raiun Testing",
            "/",
            "Raiun Testing",
            "Owner",
            listOf("ChatGPT Test"),
            listOf("2026-10-03T12:00:00Z"),
            emptyList(),
            null,
            null,
            7,
            SharedFolderAccess(setOf("libre.graph/driveItem/children/read", "libre.graph/driveItem/content/read")),
            "https://example.test/f/root",
            false,
            true,
        )

    @Test fun foldersHaveActionsInEveryLayoutAndHiddenSharesCanBeRecovered() {
        val layout = mutableStateOf(SettingsBrowserLayout.DEFAULT_TABLE)
        var opened = 0
        compose.setContent {
            OpenCloudTheme {
                IncomingBrowserScreen(
                    IncomingBrowserState(
                        account = "a",
                        items =
                            listOf(
                                folder,
                                folder.copy(
                                    name = "Hidden folder",
                                    request = folder.request.copy(share = "other"),
                                    hidden = true,
                                ),
                            ),
                    ),
                    {},
                    {},
                    {},
                    null,
                    { _, _ -> },
                    {},
                    layout = layout.value,
                    onLayout = { layout.value = it },
                    onFolderActions = {
                        assertEquals(folder, it)
                        opened++
                    },
                )
            }
        }
        compose.onAllNodesWithText("Hidden folder").assertCountEquals(0)
        compose.onNodeWithContentDescription("Actions for Raiun Testing").performClick()
        compose.onNodeWithContentDescription("Switch to compact list view").performClick()
        compose.onNodeWithContentDescription("Actions for Raiun Testing").performClick()
        compose.onNodeWithContentDescription("Switch to grid view").performClick()
        compose.onNodeWithContentDescription("Actions for Raiun Testing").performClick()
        assertEquals(3, opened)
        compose.onNodeWithText("Show hidden shares").performClick()
        compose.onAllNodesWithText("Hidden folder").assertCountEquals(1)
        compose.onNodeWithText("Hide hidden shares").performClick()
        compose.onAllNodesWithText("Hidden folder").assertCountEquals(0)
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/shared_folder_browser.png")
    }

    @Test fun folderMenuExposesDetailsLinkAndVisibilityWithoutDestructiveOwnerActions() {
        var copied = 0
        var visibility = 0
        compose.setContent {
            OpenCloudTheme {
                IncomingFolderActionSheet(details.name, details, null, {}, {}, {}, { copied++ }, { visibility++ }, {})
            }
        }
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/shared_folder_actions.png")
        compose.onNodeWithText("Copy permanent link").performClick()
        compose.onNodeWithText("Hide share").performClick()
        assertEquals(1, copied)
        assertEquals(1, visibility)
        compose.onAllNodesWithText("Delete").assertCountEquals(0)
    }

    @Test fun detailsShowActualReadAccessAndNotUploadPermission() {
        compose.setContent { OpenCloudTheme { IncomingFolderDetailsDialog(details, {}) } }
        compose.onAllNodesWithText("Download files").assertCountEquals(1)
        compose.onAllNodesWithText("Upload files").assertCountEquals(0)
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/shared_folder_details.png")
    }

    @Test fun descendantFolderDoesNotOfferShareVisibility() {
        compose.setContent {
            OpenCloudTheme {
                IncomingFolderActionSheet(
                    "Child",
                    details.copy(canChangeVisibility = false),
                    null,
                    {},
                    {},
                    {},
                    {},
                    {},
                    {},
                )
            }
        }
        compose.onAllNodesWithText("Hide share").assertCountEquals(0)
        compose.onAllNodesWithText("Copy permanent link").assertCountEquals(1)
    }
}
