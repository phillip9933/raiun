package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotDisplayed
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.feature.files.BackupFolderCrumb
import eu.opencloud.android.next.feature.files.BrowserLayout
import eu.opencloud.android.next.feature.files.FavoritesSyncStatus
import eu.opencloud.android.next.feature.files.FavoritesUiState
import eu.opencloud.android.next.feature.files.FileBrowserDestination
import eu.opencloud.android.next.feature.files.FileBrowserScreen
import eu.opencloud.android.next.feature.files.FileBrowserUiState
import eu.opencloud.android.next.feature.files.FolderBackupSettingsContent
import eu.opencloud.android.next.feature.files.FolderCrumb
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
class FileBrowserGoldenTest {
    @get:Rule
    val composeRule = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun fileBrowserList_matchesGolden() = capture(browserState())

    @Test fun projectSpaceContext_matchesGolden() {
        val state = browserState(folderTrail = listOf(FolderCrumb("notes", "Notes")))
        capture(
            state.copy(spaces = listOf(state.spaces.single().copy(type = "project", name = "Team research"))),
            "file_browser_project_space",
        )
    }

    @Test fun projectSpaceHasPersistentContextAndReturnsToSpaces() {
        val state = browserState()
        render(state.copy(spaces = listOf(state.spaces.single().copy(type = "project", name = "Team research"))))
        composeRule.onNodeWithText("Space: Team research").assertIsDisplayed()
        composeRule.onNodeWithText("All spaces").assertIsDisplayed()
        composeRule.runOnUiThread { composeRule.activity.onBackPressedDispatcher.onBackPressed() }
        composeRule.onAllNodesWithText("Space: Team research").assertCountEquals(0)
    }

    @Test fun favoritesProvidesNewActionsWithExplicitDestination() {
        var scanned = false
        render(browserState(), initialDestination = FileBrowserDestination.Favorites, onScan = { scanned = true })
        composeRule.onNodeWithContentDescription("New").performClick()
        composeRule.onNodeWithText("Add to: Personal").assertIsDisplayed()
        composeRule.onRoot().captureRoboImage("src/test/snapshots/rendered/file_browser_add_menu.png")
        composeRule.onNodeWithContentDescription("Upload file").assertIsDisplayed()
        composeRule.onAllNodesWithContentDescription("Image document").assertCountEquals(0)
        composeRule.onNodeWithContentDescription("Scan").assertIsDisplayed().performClick()
        org.junit.Assert.assertTrue(scanned)
        composeRule.onAllNodesWithContentDescription("Scan").assertCountEquals(0)
    }

    @Test fun spacesOverviewOnlyOffersCreateSpace() {
        render(browserState(), initialDestination = FileBrowserDestination.Spaces)
        composeRule.onAllNodesWithContentDescription("New").assertCountEquals(0)
        composeRule.onNodeWithContentDescription("Create space").assertIsDisplayed()
        composeRule.onAllNodesWithContentDescription("Upload file").assertCountEquals(0)
    }

    @Test fun accountAvatarUsesProfileNameInsteadOfInternalId() {
        val context = composeRule.activity.applicationContext
        context
            .getSharedPreferences("server-profile-avatars-v2", android.content.Context.MODE_PRIVATE)
            .edit()
            .putLong("account", System.currentTimeMillis())
            .commit()
        kotlinx.coroutines.runBlocking {
            eu.opencloud.android.next.core.database.FileBrowserDatabase.create(context).accountDao().upsert(
                eu.opencloud.android.next.core.database.AccountEntity(
                    "account",
                    "https://example.test",
                    "phil",
                    "Phil Rogers",
                    "BASIC",
                    false,
                ),
            )
        }
        try {
            render(browserState())
            composeRule.waitUntil(5_000) { composeRule.onAllNodesWithText("P").fetchSemanticsNodes().isNotEmpty() }
            composeRule.onAllNodesWithText("A").assertCountEquals(0)
        } finally {
            kotlinx.coroutines.runBlocking {
                eu.opencloud.android.next.core.database.FileBrowserDatabase
                    .create(
                        context,
                    ).accountDao()
                    .delete("account")
            }
        }
    }

    @Test fun systemBackNavigatesUpFromFolder() {
        var up = false
        render(browserState(folderTrail = listOf(FolderCrumb("documents", "Documents"))), onNavigateUp = { up = true })
        composeRule.runOnUiThread { composeRule.activity.onBackPressedDispatcher.onBackPressed() }
        composeRule.runOnIdle { check(up) }
    }

    @Test fun systemBackClearsSelectionBeforeNavigatingUp() {
        var cleared = false
        render(
            browserState(selectedIds = setOf("welcome"), folderTrail = listOf(FolderCrumb("documents", "Documents"))),
            onClearSelection = { cleared = true },
            onNavigateUp = { error("Selection should clear first") },
        )
        composeRule.runOnUiThread { composeRule.activity.onBackPressedDispatcher.onBackPressed() }
        composeRule.runOnIdle { check(cleared) }
    }

    @Test fun selectionOffersLocalRemovalSeparatelyFromCloudDeletion() {
        var removed = false
        render(browserState(selectedIds = setOf("welcome")), onRemoveLocalSelection = { removed = true })
        composeRule.onNodeWithContentDescription("Delete local copies").performClick()
        composeRule.runOnIdle { check(removed) }
        composeRule.onNodeWithContentDescription("Delete selected").fetchSemanticsNode()
        val actionRows =
            listOf("Move selected", "Copy selected", "Favorite selected", "Delete selected", "Delete local copies")
                .map {
                    composeRule
                        .onNodeWithContentDescription(it)
                        .fetchSemanticsNode()
                        .boundsInRoot.center.y
                }
        check(actionRows.distinct().size == 1) { "Selection actions must occupy one row" }
    }

    @Test fun imageGridUsesFullWidthPreview() {
        val photo = resource("photo", "Beach.jpg", ResourceKind.FILE).copy(mimeType = "image/jpeg")
        capture(browserState(layout = BrowserLayout.TILES).copy(resources = sampleResources() + photo))
    }

    @Test fun sortChoiceSurvivesRestoration() {
        val restoration = StateRestorationTester(composeRule)
        render(browserState(), restoration = restoration)
        composeRule.onNodeWithText("Name").performClick()
        composeRule.onNodeWithText("Size").performClick()
        restoration.emulateSavedInstanceStateRestore()
        composeRule.onNodeWithText("Size").fetchSemanticsNode()
    }

    @Test
    fun favoritesRemainingWork_canContinue() {
        var requested = false
        render(
            state = browserState(),
            favoritesState = FavoritesUiState(syncStatus = FavoritesSyncStatus.MORE),
            initialDestination = FileBrowserDestination.Favorites,
            onRefreshFavorites = { requested = true },
        )
        composeRule.onNodeWithText("More favorites may remain to be checked.").fetchSemanticsNode()
        composeRule.onNodeWithText("Continue checking").performClick()
        check(requested)
    }

    @Test
    fun favoritesRunningWork_preventsDuplicateRefresh() {
        render(
            state = browserState(),
            favoritesState = FavoritesUiState(syncStatus = FavoritesSyncStatus.RUNNING),
            initialDestination = FileBrowserDestination.Favorites,
        )
        composeRule.onNodeWithText("Checking favorites. Waiting for a connection if needed.").fetchSemanticsNode()
        composeRule.onAllNodesWithText("Refresh favorites").assertCountEquals(0)
        composeRule.onAllNodesWithText("Continue checking").assertCountEquals(0)
    }

    @Test
    fun favoritesFailure_canRetry() {
        var requested = false
        render(
            state = browserState(),
            favoritesState = FavoritesUiState(syncStatus = FavoritesSyncStatus.FAILED),
            initialDestination = FileBrowserDestination.Favorites,
            onRefreshFavorites = { requested = true },
        )
        composeRule.onNodeWithText("Favorites could not be fully refreshed. Try again.").fetchSemanticsNode()
        composeRule.onNodeWithText("Refresh favorites").performClick()
        check(requested)
    }

    @Test
    fun favoritesTopLevel_matchesGolden() {
        render(
            state = browserState(),
            favoritesState =
                FavoritesUiState(
                    listOf(
                        sampleResources().first().copy(
                            name = "Quarterly plan.pdf",
                            path = "/Documents/Quarterly plan.pdf",
                            kind = ResourceKind.FILE,
                            isFavorite = true,
                            hasLocalCopy = true,
                        ),
                    ),
                ),
        )
        composeRule.onNodeWithContentDescription("Navigate to Favorites").performClick()
        composeRule.waitForIdle()
        composeRule.onNodeWithContentDescription("Open navigation drawer").fetchSemanticsNode()
        composeRule.onNodeWithContentDescription("Navigate to Favorites").fetchSemanticsNode()
        composeRule.onAllNodesWithContentDescription("Back").assertCountEquals(0)
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/favorites.png",
            roborazziOptions = browserRoborazziOptions(),
        )
    }

    @Test
    fun fileBrowserFixedSearch_acceptsQueryWithoutChangingLayout() {
        var query = ""
        render(
            state = browserState(),
            onSearchQueryChange = { query = it },
        )

        composeRule.onNodeWithContentDescription("Filter files").performTextInput("plan")
        check(query == "plan")
    }

    @Test
    fun fileBrowserActionSheet_offersLocalRemovalForDownloadedFile() {
        render(state = browserState(actionResource = sampleResources().last()))
        composeRule.onNodeWithText("Delete local copy").fetchSemanticsNode()
        composeRule.onAllNodesWithText("Download for offline use").assertCountEquals(0)
        composeRule.onAllNodesWithText("Download").assertCountEquals(0)
        composeRule.onAllNodesWithText("Make available offline").assertCountEquals(1)
    }

    @Test fun deviceExportOffersCopyWithoutLocalMove() {
        val choices = mutableListOf<Boolean>()
        val resource = sampleResources().last()
        render(browserState(actionResource = resource), onExport = { item, move ->
            check(item.remoteId == resource.remoteId)
            choices += move
        })
        composeRule.onNodeWithText("Copy to device…").performScrollTo().performClick()
        composeRule.onAllNodesWithText("Move local copy to device…").assertCountEquals(0)
        check(choices == listOf(false))
        composeRule.onRoot().captureRoboImage(
            "src/test/snapshots/rendered/device_export_actions.png",
            browserRoborazziOptions(),
        )
    }

    @Test fun fileBrowserActionSheet_offersDownloadForCloudFile() {
        render(
            state =
                browserState(
                    actionResource = sampleResources().last().copy(hasLocalCopy = false, localPath = null),
                ),
        )
        composeRule.onNodeWithText("Make available offline").fetchSemanticsNode()
        composeRule.onAllNodesWithText("Delete local copy").assertCountEquals(0)
    }

    @Test fun compactListShowsOfflineAvailability() {
        val state = browserState(layout = BrowserLayout.CONDENSED_TABLE)
        render(
            state.copy(
                resources =
                    state.resources +
                        sampleResources().last().copy(remoteId = "kept", name = "Kept.pdf", offlinePinned = true),
            ),
        )
        composeRule.onAllNodesWithContentDescription("Temporary local copy").assertCountEquals(1)
        composeRule.onAllNodesWithContentDescription("Kept offline").assertCountEquals(1)
    }

    @Test
    fun fileBrowserAvailabilityIndicators_areIconOnly() {
        render(state = browserState())
        composeRule.onAllNodesWithContentDescription("Cloud only").assertCountEquals(2)
        composeRule.onAllNodesWithContentDescription("Temporary local copy").assertCountEquals(1)
        composeRule.onAllNodesWithText("Cloud only").assertCountEquals(0)
        composeRule.onAllNodesWithText("Temporary local copy").assertCountEquals(0)
    }

    @Test
    fun fileBrowserSearchResults_matchesGolden() =
        capture(
            browserState(
                searchQuery = "plan",
                searchResults =
                    listOf(
                        resource("plans", "Plans", ResourceKind.FOLDER),
                        resource("plan", "Quarterly plan.pdf", ResourceKind.FILE, 42),
                    ),
                remoteSearchSupported = true,
            ),
            fileName = "file_browser_search_results",
        )

    @Test
    fun fileBrowserSearchFailureHeader_matchesGolden() =
        capture(
            searchFailureState(),
            fileName = "file_browser_search_failure_header",
        ) {
            val bannerBottom =
                composeRule
                    .onNodeWithText("Transfer failed: Broken.pdf")
                    .fetchSemanticsNode()
                    .boundsInRoot.bottom
            val firstResultTop =
                composeRule
                    .onNodeWithText("Plans")
                    .fetchSemanticsNode()
                    .boundsInRoot.top
            check(firstResultTop >= bannerBottom)
        }

    @Test
    fun fileBrowserGridSelection_matchesGolden() =
        capture(browserState(layout = BrowserLayout.TILES, selectedIds = setOf("documents", "welcome")))

    @Test
    fun fileBrowserListSelection_matchesGolden() =
        capture(
            browserState(selectedIds = setOf("documents")),
            fileName = "file_browser_DEFAULT_TABLE_selection",
        )

    @Test
    fun fileBrowserCondensedTable_matchesGolden() = capture(browserState(layout = BrowserLayout.CONDENSED_TABLE))

    @Test
    fun fileBrowserNestedFolder_matchesGolden() =
        capture(
            browserState(
                folderTrail =
                    listOf(
                        FolderCrumb("documents", "Documents"),
                        FolderCrumb("reports", "Reports"),
                    ),
            ),
            fileName = "file_browser_DEFAULT_TABLE_nested_folder",
        )

    @Test
    fun fileBrowserActions_matchesGolden() = capture(browserState(actionResource = sampleResources().last()))

    @Test
    fun fileBrowserBottomNavigation_matchesGolden() =
        capture(browserState(), "file_browser_bottom_navigation") {
            listOf("Favorites", "Personal", "Spaces").forEach { label ->
                composeRule.onNodeWithContentDescription("Navigate to $label").fetchSemanticsNode()
            }
        }

    @Test
    fun fileBrowserNavigationDrawer_matchesGolden() =
        capture(browserState(), "file_browser_navigation_drawer") {
            composeRule.onNodeWithContentDescription("Open navigation drawer").performClick()
            composeRule.onNodeWithContentDescription("Navigate to Recents").fetchSemanticsNode()
            composeRule.onNodeWithContentDescription("Navigate to Offline").fetchSemanticsNode()
            composeRule.onNodeWithContentDescription("Navigate to Deleted files").fetchSemanticsNode()
            composeRule.onNodeWithContentDescription("Open Settings").fetchSemanticsNode()
            composeRule.onNodeWithText("Version 0.1.0").fetchSemanticsNode()
        }

    @Test fun offlineIsReachableFromDrawerAndHasNewActions() {
        render(browserState())
        composeRule.onNodeWithText("Offline").assertIsNotDisplayed()
        composeRule.onNodeWithContentDescription("Open navigation drawer").performClick()
        composeRule.onNodeWithContentDescription("Navigate to Offline").performClick()
        composeRule.onNodeWithText("Local space used:", substring = true).assertIsDisplayed()
        composeRule.onNodeWithContentDescription("New").performClick()
        composeRule.onNodeWithContentDescription("Upload file").assertIsDisplayed()
    }

    @Test
    fun fileBrowserBackupFolderPicker_matchesGolden() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                FolderBackupSettingsContent(
                    backups = emptyList(),
                    pickerTrail = listOf(BackupFolderCrumb("photos", "Photos", "/Photos")),
                    pickerFolders = listOf(resource("camera", "Camera", ResourceKind.FOLDER, parentId = "photos")),
                    onDismiss = {},
                    onAdd = {},
                    onDelete = {},
                )
            }
        }
        composeRule.onNodeWithText("Select folder").performClick()
        composeRule.onNodeWithText("Select remote folder").fetchSemanticsNode()
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/file_browser_backup_folder_picker.png",
            roborazziOptions = browserRoborazziOptions(),
        )
    }

    @Test
    fun fileBrowserConflict_matchesGolden() =
        capture(
            browserState(
                transfers =
                    listOf(
                        TransferEntity(
                            id = "conflict",
                            accountId = "account",
                            spaceId = "personal",
                            resourceId = null,
                            direction = TransferDirection.UPLOAD.name,
                            sourceUri = "content://example/photo.jpg",
                            destinationPath = "/Photo.jpg",
                            displayName = "Photo.jpg",
                            mimeType = "image/jpeg",
                            bytesTotal = 42,
                            state = TransferState.CONFLICT.name,
                            createdAtEpochMillis = 0,
                            updatedAtEpochMillis = 0,
                        ),
                    ),
            ),
            "file_browser_upload_conflict",
        )

    @Test
    fun fileBrowserSortOptions_matchesGolden() =
        capture(browserState(), "file_browser_sort_options") {
            composeRule.onNodeWithText("Name").performClick()
            listOf("Date modified", "Date created", "Size", "File type").forEach { label ->
                composeRule.onNodeWithText(label).fetchSemanticsNode()
            }
        }

    @Test
    fun transferSummaryOpensTransfers() {
        var opened = false
        val state = searchFailureState()
        render(state, onOpenTransfers = { opened = true })
        composeRule.onNodeWithText("Transfer failed:", substring = true).performClick()
        check(opened)
    }

    @Test
    fun discoveryFailureIsInlineRatherThanAFileOperationDialog() {
        render(browserState().copy(discoveryError = "The server could not be reached."))
        composeRule.onNodeWithText("Refresh failed:", substring = true).fetchSemanticsNode()
        composeRule.onAllNodesWithText("File operation").assertCountEquals(0)
    }

    @Test
    fun fileBrowserAccountInformation_invokesNavigation() {
        var opened = false
        render(browserState(), onOpenAccount = { opened = true })
        composeRule.onNodeWithContentDescription("Open account information").performClick()
        org.junit.Assert.assertTrue(opened)
    }

    @Test
    fun fileBrowserViewToggle_cyclesThroughAllLayouts() {
        var selectedLayout: BrowserLayout? = null
        render(browserState(), onSetLayout = { selectedLayout = it })

        composeRule.onNodeWithContentDescription("Switch to compact list view").performClick()
        check(selectedLayout == BrowserLayout.CONDENSED_TABLE)

        render(browserState(layout = BrowserLayout.CONDENSED_TABLE), onSetLayout = { selectedLayout = it })
        composeRule.onNodeWithContentDescription("Switch to grid view").performClick()
        check(selectedLayout == BrowserLayout.TILES)

        render(browserState(layout = BrowserLayout.TILES), onSetLayout = { selectedLayout = it })
        composeRule.onNodeWithContentDescription("Switch to regular list view").performClick()
        check(selectedLayout == BrowserLayout.DEFAULT_TABLE)
    }

    @Suppress("LongParameterList")
    private fun capture(
        state: FileBrowserUiState,
        fileName: String = "file_browser_${state.layout}_${state.selectedIds.size}_${state.actionResource != null}",
        onSetLayout: (BrowserLayout) -> Unit = {},
        onSearchQueryChange: (String) -> Unit = {},
        interaction: () -> Unit = {},
    ) {
        render(state, onSetLayout, onSearchQueryChange)
        interaction()
        composeRule.waitForIdle()
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/$fileName.png",
            // Robolectric anti-aliasing varies by a few host-rendered pixels; layout and color changes still fail.
            roborazziOptions = browserRoborazziOptions(),
        )
    }

    @Suppress("LongParameterList") // Independent UI callbacks and restoration are explicit test seams.
    private fun render(
        state: FileBrowserUiState,
        onSetLayout: (BrowserLayout) -> Unit = {},
        onSearchQueryChange: (String) -> Unit = {},
        favoritesState: FavoritesUiState = FavoritesUiState(),
        initialDestination: FileBrowserDestination = FileBrowserDestination.Personal,
        onRefreshFavorites: () -> Unit = {},
        restoration: StateRestorationTester? = null,
        onOpenAccount: () -> Unit = {},
        onOpenTransfers: () -> Unit = {},
        onExport: (ResourceEntity, Boolean) -> Unit = { _, _ -> },
        onNavigateUp: () -> Unit = {},
        onClearSelection: () -> Unit = {},
        onRemoveLocalSelection: () -> Unit = {},
        onScan: () -> Unit = {},
        onOpenEncryptedOffline: () -> Unit = {},
    ) {
        val content: @Composable () -> Unit = {
            OpenCloudTheme {
                FileBrowserScreen(
                    accountId = "account",
                    releaseVersion = "0.1.0",
                    state = state,
                    favoritesState = favoritesState,
                    onRefreshFavorites = onRefreshFavorites,
                    onSelectSpace = {},
                    onOpen = {},
                    onNavigateUp = onNavigateUp,
                    onSetLayout = onSetLayout,
                    onToggleSelection = {},
                    onClearSelection = onClearSelection,
                    onRemoveLocalSelection = onRemoveLocalSelection,
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
                    onScan = onScan,
                    onDownloadForOffline = {},
                    onToggleFavorite = {},
                    onResolveConflict = { _, _ -> },
                    onClearMessage = {},
                    onSearchQueryChange = onSearchQueryChange,
                    onOpenTransfers = onOpenTransfers,
                    onOpenDeletedFiles = {},
                    onOpenSettings = {},
                    onOpenAccount = onOpenAccount,
                    onOpenEncryptedOffline = onOpenEncryptedOffline,
                    onShareResource = {},
                    onExport = onExport,
                    initialDestination = initialDestination,
                )
            }
        }
        if (restoration == null) composeRule.activity.setContent(content = content) else restoration.setContent(content)
        composeRule.waitForIdle()
    }

    @Test fun offlineFiltersSeparateTemporaryAndPinnedCopies() {
        val file = sampleResources().last()
        render(
            browserState().copy(
                resources = emptyList(),
                offlineResources =
                    listOf(
                        file.copy(remoteId = "temporary", name = "Opened.jpg"),
                        file.copy(remoteId = "pinned", name = "Retained.jpg", offlinePinned = true),
                    ),
            ),
            initialDestination = FileBrowserDestination.Offline,
        )
        composeRule.onNodeWithText("Kept offline").performClick()
        composeRule.onAllNodesWithText("Opened.jpg").assertCountEquals(0)
        composeRule.onNodeWithText("Retained.jpg").assertIsDisplayed()
        composeRule.onNodeWithText("Temporary").performClick()
        composeRule.onAllNodesWithText("Retained.jpg").assertCountEquals(0)
        composeRule.onNodeWithText("Opened.jpg").assertIsDisplayed()
        composeRule.onAllNodesWithText("Remove local copies").assertCountEquals(0)
        composeRule.onRoot().captureRoboImage(
            "src/test/snapshots/rendered/offline_filters.png",
            browserRoborazziOptions(),
        )
    }

    @Test fun offlineScreenClearlyRoutesToEncryptedOfflineCopies() {
        var openedEncryptedCatalog = false
        render(
            browserState().copy(resources = emptyList(), offlineResources = emptyList()),
            initialDestination = FileBrowserDestination.Offline,
            onOpenEncryptedOffline = { openedEncryptedCatalog = true },
        )

        composeRule.onNodeWithText("Encrypted offline copies").assertIsDisplayed().performClick()
        assertEquals(true, openedEncryptedCatalog)
    }

    @Test fun offlineStorageAndBulkActions_matchesGolden() {
        var removed = false
        val resource = sampleResources().last()
        render(
            browserState(selectedIds = setOf(resource.remoteId)).copy(
                resources = emptyList(),
                offlineResources = listOf(resource),
                offlineBytes = resource.sizeBytes,
            ),
            initialDestination = FileBrowserDestination.Offline,
            onRemoveLocalSelection = { removed = true },
        )
        composeRule.onNodeWithContentDescription("Delete local copies").performClick()
        assertEquals(true, removed)
        composeRule.onNodeWithText("Local space used:", substring = true).assertIsDisplayed()
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/offline_storage_selection.png",
            roborazziOptions = browserRoborazziOptions(),
        )
    }

    @Test fun sharedTransfersUseTheSameVisibleProgressAndQueueNavigation() {
        var opened = false
        val transfer =
            searchFailureState().transfers.single().copy(
                state = TransferState.RUNNING.name,
                locationKind = "SHARED_FOLDER",
                bytesTotal = 100000000,
                bytesTransferred = 40000000,
                displayName = "Large.apk",
            )
        render(
            browserState(transfers = listOf(transfer)),
            initialDestination = FileBrowserDestination.Shares,
            onOpenTransfers = { opened = true },
        )
        composeRule.onNodeWithText("Large.apk", substring = true).assertIsDisplayed().performClick()
        assertEquals(true, opened)
        composeRule.onAllNodesWithText("Preparing").assertCountEquals(0)
        composeRule.onAllNodesWithContentDescription("New").assertCountEquals(0)
        composeRule.onRoot().captureRoboImage("src/test/snapshots/rendered/shared_transfer_progress.png")
    }

    @Test fun spacesTransfersAlsoShowTheCommonQueueStatus() {
        var opened = false
        render(
            searchFailureState(),
            initialDestination = FileBrowserDestination.Spaces,
            onOpenTransfers = { opened = true },
        )
        composeRule.onNodeWithText("Transfer failed:", substring = true).assertIsDisplayed().performClick()
        assertEquals(true, opened)
    }

    private fun browserRoborazziOptions() =
        RoborazziOptions(
            compareOptions =
                RoborazziOptions.CompareOptions(
                    resultValidator = { result ->
                        result.pixelDifferences.toFloat() / result.pixelCount <= 0.001f
                    },
                ),
        )
}

@Suppress("LongParameterList")
private fun browserState(
    layout: BrowserLayout = BrowserLayout.DEFAULT_TABLE,
    selectedIds: Set<String> = emptySet(),
    actionResource: ResourceEntity? = null,
    folderTrail: List<FolderCrumb> = emptyList(),
    transfers: List<TransferEntity> = emptyList(),
    searchQuery: String = "",
    searchResults: List<ResourceEntity> = emptyList(),
    remoteSearchSupported: Boolean = false,
) = FileBrowserUiState(
    spaces =
        listOf(
            SpaceEntity(
                "account",
                "personal",
                "Personal",
                "personal",
                "Your private files",
                null,
                "root",
                null,
                null,
                null,
            ),
        ),
    spaceId = "personal",
    resources = sampleResources(),
    layout = layout,
    selectedIds = selectedIds.map { "personal\u0000$it" }.toSet(),
    actionResource = actionResource,
    folderTrail = folderTrail,
    transfers = transfers,
    searchQuery = searchQuery,
    searchResults = searchResults,
    remoteSearchSupported = remoteSearchSupported,
)

private fun sampleResources() =
    listOf(
        resource("documents", "Documents", ResourceKind.FOLDER),
        resource("photos", "Photos", ResourceKind.FOLDER),
        resource("welcome", "Welcome to OpenCloud.pdf", ResourceKind.FILE, 1_258_291).copy(hasLocalCopy = true),
    )

private fun searchFailureState() =
    browserState(
        searchQuery = "plan",
        searchResults =
            listOf(
                resource("plans", "Plans", ResourceKind.FOLDER),
                resource("plan", "Quarterly plan.pdf", ResourceKind.FILE, 42),
            ),
        transfers =
            listOf(
                TransferEntity(
                    id = "failed",
                    accountId = "account",
                    spaceId = "personal",
                    resourceId = "broken",
                    direction = TransferDirection.DOWNLOAD.name,
                    sourceUri = null,
                    destinationPath = "/Broken.pdf",
                    displayName = "Broken.pdf",
                    mimeType = "application/pdf",
                    bytesTotal = 42,
                    state = TransferState.FAILED.name,
                    error = "Network connection lost.",
                    createdAtEpochMillis = 0,
                    updatedAtEpochMillis = 0,
                ),
            ),
    )

private fun resource(
    id: String,
    name: String,
    kind: ResourceKind,
    size: Long = 0,
    parentId: String? = null,
) = ResourceEntity(
    "account",
    "personal",
    id,
    parentId,
    "/$name",
    name,
    kind,
    null,
    size,
    null,
    1_700_000_000_000,
    1_700_000_000_000,
)
