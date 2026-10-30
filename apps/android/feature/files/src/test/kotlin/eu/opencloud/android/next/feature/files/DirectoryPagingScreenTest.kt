package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import eu.opencloud.android.next.core.database.ResourceDirectoryItem
import eu.opencloud.android.next.core.database.ResourceDirectoryPage
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class DirectoryPagingScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun `page controls display global total and retain explicit selection and its actions off page`() {
        val first = resource("first").copy(hasLocalCopy = true, localPath = "/synthetic/first")
        val second = resource("second")
        var state by mutableStateOf(pageState(first, 0))
        compose.setContent {
            Browser(
                state,
                onPage = { previous ->
                    state =
                        pageState(if (previous) first else second, if (previous) 0 else 128)
                            .copy(selectedIds = state.selectedIds)
                            .withRetainedSelection(state.selectedResources)
                },
                onSelect = { key ->
                    state =
                        state.copy(selectedIds = state.selectedIds + key).withRetainedSelection(state.selectedResources)
                },
            )
        }
        compose.onNodeWithText("1–1 of 300").assertIsDisplayed()
        compose.onNodeWithText("Previous").assertIsNotEnabled()
        compose.onNodeWithText("first").performTouchInput { longClick() }
        compose.onNodeWithText("Next").performClick()
        compose.onNodeWithText("129–129 of 300").assertIsDisplayed()
        compose.onNodeWithText("second").assertIsDisplayed()
        compose.onNodeWithContentDescription("Delete local copies").assertIsDisplayed()
        compose.runOnIdle {
            assertEquals(setOf(first.selectionKey), state.selectedIds)
            assertEquals(listOf(first), state.selectedResources)
        }
        compose.onNodeWithText("Previous").performClick()
        compose.onNodeWithText("first").assertIsDisplayed()
    }

    @Test fun `sort choice reaches global database ordering callback`() {
        val selections = mutableListOf<Pair<String, Boolean>>()
        compose.setContent {
            Browser(pageState(resource("row"), 0), onSort = { criterion, ascending ->
                selections +=
                    criterion to ascending
            })
        }
        compose.onNodeWithText("Name").performClick()
        compose.onNodeWithText("Size").performClick()
        compose.runOnIdle { assertEquals("Size" to true, selections.last()) }
        compose.onNodeWithText("Size").performClick()
        // Toolbar and dropdown both contain the current label while the menu is open.
        compose.onNodeWithContentDescription("Selected").performClick()
        compose.runOnIdle { assertEquals("Size" to false, selections.last()) }
    }

    @Test fun `Favorites page controls display cached total and use its page callback`() {
        var favorites by mutableStateOf(
            FavoritesUiState(
                resources = listOf(resource("favorite-first")),
                page =
                    ResourceDirectoryPage(
                        0,
                        300,
                        listOf(ResourceDirectoryItem(resource = resource("favorite-first"))),
                    ),
            ),
        )
        compose.setContent {
            Browser(
                FileBrowserUiState(),
                favorites = favorites,
                destination = FileBrowserDestination.Favorites,
                onFavoritePage = {
                    val row = resource("favorite-next")
                    favorites =
                        favorites.copy(
                            resources = listOf(row),
                            page = ResourceDirectoryPage(128, 300, listOf(ResourceDirectoryItem(resource = row))),
                        )
                },
            )
        }
        compose.onNodeWithText("1–1 of 300").assertIsDisplayed()
        compose.onNodeWithText("Next").performClick()
        compose.onNodeWithText("129–129 of 300").assertIsDisplayed()
        compose.onNodeWithText("favorite-next").assertIsDisplayed()
    }

    @Test fun `ordinary Offline shows full cached total independent of current page and filter routes to query`() {
        val row = resource("offline-row").copy(hasLocalCopy = true, localPath = "/synthetic/offline")
        var filter = ""
        var paged = false
        compose.setContent {
            Browser(
                FileBrowserUiState(
                    offlineResources = listOf(row),
                    offlinePage = ResourceDirectoryPage(128, 300, listOf(ResourceDirectoryItem(resource = row))),
                ),
                destination = FileBrowserDestination.Offline,
                onOfflinePage = { paged = true },
                onOfflineDisplay = { _, _, _, _, selected -> filter = selected },
            )
        }
        compose.onNodeWithText("129–129 of 300").assertIsDisplayed()
        compose.onNodeWithText("Next").performClick()
        compose.onNodeWithText("Temporary").performClick()
        compose.runOnIdle {
            assertEquals(true, paged)
            assertEquals("TEMPORARY", filter)
        }
    }

    @Test
    @Config(qualifiers = "w320dp-h800dp")
    fun largeFontPagingKeepsBothButtonsAndFabReachable() {
        val requests = mutableListOf<Boolean>()
        val row = resource("large-inventory")
        val page = ResourceDirectoryPage(1_999_999_744, 2_000_000_000, listOf(ResourceDirectoryItem(resource = row)))
        compose.setContent {
            CompositionLocalProvider(LocalDensity provides Density(LocalDensity.current.density, 2f)) {
                Browser(FileBrowserUiState(resources = listOf(row), directoryPage = page), onPage = { requests += it })
            }
        }
        val layouts = mutableListOf<TextLayoutResult>()
        val layoutAction =
            compose
                .onNodeWithText("Previous", useUnmergedTree = true)
                .fetchSemanticsNode()
                .config[SemanticsActions.GetTextLayoutResult]
                .action
        compose.runOnIdle { assertTrue(requireNotNull(layoutAction).invoke(layouts)) }
        val density = layouts.single().layoutInput.density
        assertEquals(2f, density.fontScale, 0f)
        assertEquals(
            320f,
            compose
                .onRoot()
                .fetchSemanticsNode()
                .boundsInRoot.width / density.density,
            1f,
        )
        compose.onNodeWithText("Previous").assertIsDisplayed().performClick()
        compose.onNodeWithText("Next").assertIsDisplayed().performClick()
        compose.runOnIdle { assertEquals(listOf(true, false), requests) }
        compose.onNodeWithContentDescription("New").assertIsDisplayed().performClick()
        compose.onNodeWithContentDescription("Close new actions").assertIsDisplayed().performClick()
    }

    @Composable
    @Suppress("LongMethod", "LongParameterList") // Independent route controls are explicit in this UI fixture.
    private fun Browser(
        state: FileBrowserUiState,
        onPage: (Boolean) -> Unit = {},
        onSelect: (String) -> Unit = {},
        onSort: (String, Boolean) -> Unit = { _, _ -> },
        favorites: FavoritesUiState = FavoritesUiState(),
        destination: FileBrowserDestination = FileBrowserDestination.Personal,
        onFavoritePage: (Boolean) -> Unit = {},
        onOfflinePage: (Boolean) -> Unit = {},
        onOfflineDisplay: (String, String, Boolean, Boolean, String) -> Unit = { _, _, _, _, _ -> },
    ) = OpenCloudTheme {
        FileBrowserScreen(
            accountId = "account",
            releaseVersion = "test",
            state = state,
            favoritesState = favorites,
            initialDestination = destination,
            onFavoritesPage = onFavoritePage,
            onOfflinePage = onOfflinePage,
            onOfflineDisplay = onOfflineDisplay,
            onSelectSpace = {},
            onOpen = {},
            onNavigateUp = {},
            onSetLayout = {},
            onToggleSelection = onSelect,
            onClearSelection = {},
            onDownloadSelection = {},
            onDeleteSelection = {},
            onShowActions = {},
            onDismissActions = {},
            onCreateFolder = {},
            onCreateSpace = {},
            onRename = { _, _ -> },
            onMove = {},
            onCopy = {},
            onDelete = {},
            onUpload = {},
            onDownloadForOffline = {},
            onToggleFavorite = {},
            onResolveConflict = { _, _ -> },
            onClearMessage = {},
            onSearchQueryChange = {},
            onOpenTransfers = {},
            onOpenDeletedFiles = {},
            onOpenSettings = {},
            onOpenAccount = {},
            onShareResource = {},
            onDirectoryPage = onPage,
            onDirectorySort = onSort,
        )
    }

    private fun pageState(
        row: ResourceEntity,
        offset: Int,
    ) = FileBrowserUiState(
        spaceId = "space",
        resources = listOf(row),
        directoryPage = ResourceDirectoryPage(offset, 300, listOf(ResourceDirectoryItem(resource = row))),
    )

    private fun resource(id: String) =
        ResourceEntity(
            "account",
            "space",
            id,
            null,
            id,
            id,
            ResourceKind.FILE,
            "text/plain",
            1,
            "tag",
            1,
            1,
        )
}
