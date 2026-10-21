package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.test.swipeDown
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.files.DeletedFilesBin
import eu.opencloud.android.next.feature.files.DeletedFilesScreen
import eu.opencloud.android.next.feature.files.DeletedFilesUiState
import eu.opencloud.android.next.feature.spaces.SpaceAction
import eu.opencloud.android.next.feature.spaces.SpacesScreen
import eu.opencloud.android.next.feature.spaces.SpacesUiState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@org.robolectric.annotation.GraphicsMode(org.robolectric.annotation.GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class SpaceMenusTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun overflowOpensCorrectRecycleBinWithoutOpeningTheSpace() {
        var opened: String? = null
        var action: Pair<String, SpaceAction>? = null
        compose.setContent {
            OpenCloudTheme {
                SpacesScreen(
                    SpacesUiState(spaces = listOf(space("one", "First"), space("two", "Second")), loading = false),
                    onOpenSpace = { opened = it },
                    onAction = { space, selected -> action = space.driveId to selected },
                )
            }
        }
        compose.onNodeWithContentDescription("Actions for Second").performClick()
        compose.mainClock.advanceTimeBy(500)
        compose.waitForIdle()
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/space_context_menu.png")
        compose.onNodeWithText("Open recycle bin").performClick()
        assertEquals("two" to SpaceAction.TRASH, action)
        assertEquals(null, opened)
    }

    @Test fun disabledSpaceOffersEnableAndDeleteButNotOpen() {
        compose.setContent {
            OpenCloudTheme {
                SpacesScreen(
                    SpacesUiState(spaces = listOf(space("one", "First").copy(isDisabled = true)), loading = false),
                    {},
                )
            }
        }
        compose.onNodeWithContentDescription("Actions for First").performClick()
        compose.onNodeWithText("Enable space").assertExists()
        compose.onNodeWithText("Delete space permanently").assertExists()
        compose.onNodeWithText("Open").assertDoesNotExist()
        compose.onNodeWithText("Rename").assertDoesNotExist()
    }

    @Test fun overviewSelectsSpaceAndDoesNotOfferCrossSpaceEmptyAction() {
        var selected: String? = null
        compose.setContent {
            OpenCloudTheme {
                DeletedFilesScreen(
                    DeletedFilesUiState(
                        bins =
                            listOf(
                                DeletedFilesBin("personal", "Phil", true, 3, true),
                                DeletedFilesBin("project", "Project Mars", false, 2, true),
                            ),
                    ),
                    {},
                    {},
                    {},
                    {},
                    {},
                    onOpenBin = { selected = it },
                )
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/trash_bin_overview.png")
        compose.onNodeWithText("Personal").assertExists()
        compose.onNodeWithText("Empty recycle bin").assertDoesNotExist()
        compose.onNodeWithText("Project Mars").performClick()
        assertEquals("project", selected)
    }

    @Test fun emptyAndPopulatedSpacesCanRefreshBySwipeAndButton() {
        val rows = androidx.compose.runtime.mutableStateOf(emptyList<SpaceEntity>())
        var refreshes = 0
        compose.setContent {
            OpenCloudTheme {
                SpacesScreen(SpacesUiState(spaces = rows.value, loading = false), {}, onRefresh = { refreshes++ })
            }
        }
        compose.onRoot().performTouchInput { swipeDown(startY = centerY / 2, endY = height * 0.9f) }
        compose.waitForIdle()
        assertEquals(1, refreshes)
        compose.onNodeWithContentDescription("Refresh").performClick()
        assertEquals(2, refreshes)
        compose.runOnIdle { rows.value = listOf(space("new", "New space")) }
        compose.onRoot().performTouchInput { swipeDown(startY = centerY / 2, endY = height * 0.9f) }
        compose.waitForIdle()
        assertEquals(3, refreshes)
    }

    @Test fun membersAndDownloadTargetTheSelectedSpace() {
        var selected: Pair<String, SpaceAction>? = null
        compose.setContent {
            OpenCloudTheme {
                SpacesScreen(
                    SpacesUiState(spaces = listOf(space("team", "Team")), loading = false),
                    {},
                    onAction = { space, action -> selected = space.driveId to action },
                )
            }
        }
        compose.onNodeWithContentDescription("Actions for Team").performClick()
        compose.onNodeWithText("Members").performClick()
        assertEquals("team" to SpaceAction.MEMBERS, selected)
        compose.onNodeWithContentDescription("Actions for Team").performClick()
        compose.onNodeWithText("Download space").performClick()
        assertEquals("team" to SpaceAction.DOWNLOAD, selected)
    }

    private fun space(
        id: String,
        name: String,
    ) = SpaceEntity(
        accountId = "account",
        driveId = id,
        name = name,
        type = "project",
        description = null,
        ownerName = "Owner",
        rootId = id,
        rootWebDavUrl = "https://cloud.example/dav/$id",
        rootETag = null,
        quotaBytes = 1024,
    )
}
