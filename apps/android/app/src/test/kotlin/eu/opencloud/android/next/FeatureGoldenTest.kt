package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.ShareEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferDirection
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.RemoteTrashResource
import eu.opencloud.android.next.feature.account.AccountScreen
import eu.opencloud.android.next.feature.account.AccountUiState
import eu.opencloud.android.next.feature.files.DeletedFilesScreen
import eu.opencloud.android.next.feature.files.DeletedFilesUiState
import eu.opencloud.android.next.feature.search.SearchScreen
import eu.opencloud.android.next.feature.search.SearchUiState
import eu.opencloud.android.next.feature.settings.SettingsScreen
import eu.opencloud.android.next.feature.shares.ResourceSharesScreen
import eu.opencloud.android.next.feature.shares.ShareCategory
import eu.opencloud.android.next.feature.shares.SharesScreen
import eu.opencloud.android.next.feature.shares.SharesUiState
import eu.opencloud.android.next.feature.spaces.SpacesScreen
import eu.opencloud.android.next.feature.spaces.SpacesUiState
import eu.opencloud.android.next.feature.transfers.TransfersScreen
import eu.opencloud.android.next.feature.transfers.TransfersUiState
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
class FeatureGoldenTest {
    @get:Rule
    val timeZoneRule = GoldenTimeZoneRule("Asia/Tokyo")

    @get:Rule
    val composeRule = createAndroidComposeRule<ComponentActivity>()

    @Test fun searchEmpty_matchesGolden() = captureSearch(SearchUiState(), "search_empty")

    @Test fun searchLoading_matchesGolden() =
        captureSearch(
            SearchUiState(query = "quarterly plan", remoteSupported = true, isRemoteLoading = true),
            "search_loading",
        )

    @Test fun searchResults_matchesGolden() =
        captureSearch(
            SearchUiState(
                query = "plan",
                remoteSupported = true,
                resources =
                    listOf(
                        resource("plans", "Plans", ResourceKind.FOLDER, "/Projects/Plans"),
                        resource("plan", "Quarterly plan.pdf", ResourceKind.FILE, "/Projects/Quarterly plan.pdf"),
                    ),
            ),
            "search_results",
        )

    @Test fun transfersEmpty_matchesGolden() = captureTransfers(TransfersUiState(), "transfers_empty")

    @Test
    fun retryingTransfer_exposesPerTransferRetryAction() {
        renderTransfers(
            TransfersUiState(
                active = listOf(transfer(TransferFixture("retry", "Retrying.xlsx", TransferState.RETRY, 0, 80))),
            ),
        )

        composeRule.onNodeWithContentDescription("Retry").assertIsDisplayed()
    }

    @Test fun spacesEmpty_matchesGolden() =
        capture("spaces_empty") {
            SpacesScreen(SpacesUiState(loading = false), onOpenSpace = {})
        }

    @Test fun spacesLoading_matchesGolden() =
        capture("spaces_loading") {
            SpacesScreen(SpacesUiState(loading = true), onOpenSpace = {})
        }

    @Test fun spacesPopulated_matchesGolden() =
        capture("spaces_populated") {
            SpacesScreen(
                state =
                    SpacesUiState(
                        loading = false,
                        spaces =
                            listOf(
                                space("personal", "Personal", "Your private files", "Alice", 64, 36),
                                space("mars", "Project Mars", "Mission planning and research", "Engineering", 72, 28),
                                space("brand", "Brand assets", null, "Design team", 18, 82),
                            ),
                    ),
                onOpenSpace = {},
            )
        }

    @Test
    fun spacesSelection_emitsDriveId() {
        var selectedSpaceId: String? = null
        composeRule.activity.setContent {
            OpenCloudTheme {
                SpacesScreen(
                    state =
                        SpacesUiState(
                            loading = false,
                            spaces = listOf(space("mars", "Project Mars", null, "Engineering", 72, 28)),
                        ),
                    onOpenSpace = { selectedSpaceId = it },
                )
            }
        }

        composeRule.onNodeWithContentDescription("Open Space Project Mars").performClick()

        assertEquals("mars", selectedSpaceId)
    }

    @Test fun deletedFiles_matchesGolden() =
        capture("deleted_files") {
            DeletedFilesScreen(
                DeletedFilesUiState(
                    activeSpaceId = "space",
                    resources =
                        listOf(
                            RemoteTrashResource(
                                "trash",
                                "space",
                                "Old report.pdf",
                                "/Documents/Old report.pdf",
                                false,
                                0,
                            ),
                        ),
                ),
                onNavigateBack = {},
                onRefresh = {},
                onRestore = {},
                onDelete = {},
                onDismissError = {},
            )
        }

    @Test fun deletedFilesUnsupported_matchesGolden() =
        capture("deleted_files_unsupported") {
            DeletedFilesScreen(DeletedFilesUiState(supported = false), {}, {}, {}, {}, {})
        }

    @Test fun trashBulkActionsKeepSpaceIdentityAndRequireDeleteConfirmation() {
        val resources =
            listOf(
                RemoteTrashResource("same", "one", "First.pdf", "/First.pdf", false, 0, 1024),
                RemoteTrashResource("second", "one", "Second.pdf", "/Second.pdf", false, 0, 2048),
            )
        var restored = emptyList<RemoteTrashResource>()
        var deleted = emptyList<RemoteTrashResource>()
        composeRule.activity.setContent {
            OpenCloudTheme {
                DeletedFilesScreen(
                    DeletedFilesUiState(resources = resources, activeSpaceId = "one"),
                    {},
                    {},
                    {},
                    {},
                    {},
                    onRestoreMany = { restored = it },
                    onDeleteMany = { deleted = it },
                )
            }
        }
        composeRule.onNodeWithText("Select all").performClick()
        composeRule.onNodeWithContentDescription("Restore selected").performClick()
        assertEquals(resources, restored)
        composeRule.onNodeWithContentDescription("Permanently delete selected").performClick()
        assertEquals(emptyList<RemoteTrashResource>(), deleted)
        composeRule.onNodeWithText("Cancel").performClick()
        composeRule.onNodeWithText("Clear selection").performClick()
        composeRule.onNodeWithText("Empty recycle bin").performClick()
        assertEquals(emptyList<RemoteTrashResource>(), deleted)
        composeRule.onNodeWithText("Delete permanently").performClick()
        assertEquals(resources, deleted)
    }

    @Test fun darkSettings_matchesGolden() =
        capture("settings_dark") {
            OpenCloudTheme(darkTheme = true) {
                SettingsScreen(
                    UserSettings(appearance = eu.opencloud.android.next.core.datastore.Appearance.DARK),
                    {},
                    {},
                    {},
                )
            }
        }

    @Test fun settings_matchesGolden() =
        capture("settings") {
            SettingsScreen(UserSettings(SettingsBrowserLayout.TILES, "account", 30), {}, {}, {})
        }

    @Test fun accounts_matchesGolden() =
        capture("accounts") {
            AccountScreen(
                AccountUiState(
                    accounts =
                        listOf(
                            AccountEntity(
                                "account",
                                "https://cloud.example",
                                "alice",
                                "Alice",
                                "OIDC",
                                true,
                            ),
                            AccountEntity(
                                "account-2",
                                "https://team.example",
                                "bob",
                                "Bob",
                                "BASIC",
                                false,
                            ),
                        ),
                    activeAccountId = "account",
                ),
                onNavigateBack = {},
                onSelect = {},
                onRemove = {},
                onAddAccount = {},
                onDismissError = {},
            )
        }

    @Test fun sharesEmpty_matchesGolden() =
        capture("shares_empty") {
            SharesScreen(
                state = SharesUiState(category = ShareCategory.WITH_ME),
                onNavigateBack = {},
                onCategory = {},
                onRefresh = {},
                onUpdatePermissions = { _, _ -> },
                onRevoke = {},
                onDismissNotice = {},
            )
        }

    @Test fun sharesLists_matchesGolden() =
        capture("shares_lists") {
            SharesScreen(
                state =
                    SharesUiState(
                        category = ShareCategory.BY_ME,
                        shares =
                            listOf(
                                share("user-share", 0, "Design team", "/Projects/Roadmap.pdf", 3),
                                share("group-share", 1, "Marketing", "/Campaign", 31, folder = true),
                                share("link-share", 3, "Board review", "/Board notes.pdf", 1),
                            ),
                    ),
                onNavigateBack = {},
                onCategory = {},
                onRefresh = {},
                onUpdatePermissions = { _, _ -> },
                onRevoke = {},
                onDismissNotice = {},
            )
        }

    @Test fun shareDetailsShowsResourceAndScope_matchesGolden() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                SharesScreen(
                    state =
                        SharesUiState(
                            category = ShareCategory.PUBLIC,
                            shares =
                                listOf(
                                    share("folder-link", 3, "Design review", "/Projects/Campaign", 1, folder = true),
                                ),
                        ),
                    onNavigateBack = {},
                    onCategory = {},
                    onRefresh = {},
                    onUpdatePermissions = { _, _ -> },
                    onRevoke = {},
                    onDismissNotice = {},
                )
            }
        }
        composeRule.onNodeWithContentDescription("Actions for Design review").performClick()
        composeRule.onNodeWithText("Details").performClick()
        composeRule.onNodeWithText("Share name").assertIsDisplayed()
        composeRule.onNodeWithText("/Projects/Campaign").assertIsDisplayed()
        composeRule.onNodeWithText("Expires: No expiration").assertIsDisplayed()
        composeRule.onRoot().captureRoboImage(snapshotPath("share_details"), featureRoborazziOptions())
    }

    @Test fun shareSheet_matchesGolden() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                ResourceSharesScreen(
                    state =
                        SharesUiState(
                            account = sharingAccount(),
                            resource = resource("roadmap", "Roadmap.pdf", ResourceKind.FILE, "/Projects/Roadmap.pdf"),
                            recipients =
                                listOf(
                                    eu.opencloud.android.next.core.network.ShareRecipient(
                                        eu.opencloud.android.next.core.network.OcsShareType.USER,
                                        "alice",
                                        "Alice Adams",
                                        "alice@example.test",
                                        true,
                                    ),
                                    eu.opencloud.android.next.core.network.ShareRecipient(
                                        eu.opencloud.android.next.core.network.OcsShareType.GROUP,
                                        "design",
                                        "Design team",
                                        null,
                                        false,
                                    ),
                                ),
                        ),
                    onNavigateBack = {},
                    onSearch = {},
                    onCreateRecipient = { _, _ -> },
                    onCreatePublic = { _, _, _, _ -> },
                    onUpdatePermissions = { _, _ -> },
                    onRevoke = {},
                    onDismissNotice = {},
                    initialInviteOpen = true,
                )
            }
        }
        composeRule.waitForIdle()
        composeRule.onRoot().captureRoboImage(
            filePath = snapshotPath("share_sheet"),
            roborazziOptions = featureRoborazziOptions(),
        )
    }

    @Test
    @Config(sdk = [35], qualifiers = "w360dp-h400dp")
    fun publicLinkControlsRemainReachableInShortViewport() {
        var createdPermissions: Int? = null
        composeRule.activity.setContent {
            OpenCloudTheme {
                ResourceSharesScreen(
                    state =
                        SharesUiState(
                            account = sharingAccount(),
                            resource = resource("roadmap", "Roadmap.pdf", ResourceKind.FILE, "/Projects/Roadmap.pdf"),
                        ),
                    onNavigateBack = {},
                    onSearch = {},
                    onCreateRecipient = { _, _ -> },
                    onCreatePublic = { _, _, _, permissions -> createdPermissions = permissions },
                    onUpdatePermissions = { _, _ -> },
                    onRevoke = {},
                    onDismissNotice = {},
                )
            }
        }
        composeRule.onNodeWithText("Create public link", substring = true).performScrollTo().performClick()
        composeRule.onNodeWithText("Password (required)").performScrollTo().performTextInput("Example?Case123")
        composeRule.onNodeWithText("View and download").performScrollTo().assertIsDisplayed()
        composeRule.onNodeWithText("Create link", substring = true).performScrollTo().assertIsDisplayed()
        composeRule.onRoot().captureRoboImage(snapshotPath("public_link_short_viewport"), featureRoborazziOptions())
        composeRule.onNodeWithText("View and edit").performScrollTo().performClick()
        composeRule.onNodeWithText("Create link", substring = true).performScrollTo().performClick()
        check(createdPermissions == 3)
    }

    @Test fun transfersActive_matchesGolden() =
        captureTransfers(
            TransfersUiState(
                active =
                    listOf(
                        transfer(TransferFixture("upload", "Roadmap.pdf", TransferState.RUNNING, 42, 100)),
                        transfer(
                            TransferFixture(
                                "download",
                                "Photos.zip",
                                TransferState.QUEUED,
                                0,
                                250,
                                TransferDirection.DOWNLOAD,
                            ),
                        ),
                    ),
            ),
            "transfers_active",
        )

    @Test fun transfersFailed_matchesGolden() =
        captureTransfers(
            TransfersUiState(
                failed =
                    listOf(
                        transfer(
                            TransferFixture(
                                "failed",
                                "Budget.xlsx",
                                TransferState.FAILED,
                                12,
                                80,
                                error = "Network connection lost.",
                            ),
                        ),
                        transfer(TransferFixture("conflict", "Notes.txt", TransferState.CONFLICT, 0, 10)),
                    ),
            ),
            "transfers_failed",
        )

    @Test fun transfers_exposesRetryButtonAndClearOverflowAction() {
        renderTransfers(failedTransfersState())
        composeRule.onNodeWithText("Retry eligible uploads").fetchSemanticsNode()
        composeRule.onNodeWithContentDescription("Transfer actions").performClick()
        composeRule.onNodeWithText("Clear all").fetchSemanticsNode()
    }

    @Test fun transfersActions_matchesGolden() {
        renderTransfers(failedTransfersState())
        composeRule.onNodeWithContentDescription("Transfer actions").performClick()
        composeRule.waitForIdle()
        composeRule.onRoot().captureRoboImage(
            filePath = snapshotPath("transfers_actions"),
            roborazziOptions = featureRoborazziOptions(),
        )
    }

    private fun captureSearch(
        state: SearchUiState,
        fileName: String,
    ) {
        composeRule.activity.setContent {
            OpenCloudTheme {
                SearchScreen(
                    state = state,
                    onQueryChange = {},
                    onNavigateBack = {},
                    onShowActions = {},
                    onDismissActions = {},
                    onDownloadForOffline = {},
                    onUnavailableAction = {},
                    onDismissMessage = {},
                )
            }
        }
        composeRule.waitForIdle()
        composeRule.onRoot().captureRoboImage(
            filePath = snapshotPath(fileName),
            roborazziOptions = featureRoborazziOptions(),
        )
    }

    private fun captureTransfers(
        state: TransfersUiState,
        fileName: String,
    ) {
        renderTransfers(state)
        composeRule.onRoot().captureRoboImage(
            filePath = snapshotPath(fileName),
            roborazziOptions = featureRoborazziOptions(),
        )
    }

    private fun capture(
        fileName: String,
        content: @androidx.compose.runtime.Composable () -> Unit,
    ) {
        composeRule.activity.setContent { OpenCloudTheme { content() } }
        composeRule.waitForIdle()
        composeRule.onRoot().captureRoboImage(snapshotPath(fileName), featureRoborazziOptions())
    }

    private fun renderTransfers(state: TransfersUiState) {
        composeRule.activity.setContent {
            OpenCloudTheme {
                TransfersScreen(
                    state = state,
                    onNavigateBack = {},
                    onRetry = {},
                    onCancel = {},
                    onResolveConflict = { _, _ -> },
                    onRetryAll = {},
                    onClearAll = {},
                    onDismissError = {},
                )
            }
        }
        composeRule.waitForIdle()
    }

    private fun resource(
        id: String,
        name: String,
        kind: ResourceKind,
        path: String,
    ) = ResourceEntity("account", "space", id, null, path, name, kind, null, 42, null, 0, 0)

    @Suppress("LongParameterList")
    private fun share(
        id: String,
        type: Int,
        displayName: String,
        path: String,
        permissions: Int,
        folder: Boolean = false,
    ) = ShareEntity(
        accountId = "account",
        remoteId = id,
        resourceId = "resource-$id",
        path = path,
        shareType = type,
        shareWith = displayName.lowercase().replace(' ', '-'),
        displayName = displayName,
        additionalInfo = null,
        permissions = permissions,
        sharedAtEpochSeconds = 1_700_000_000,
        expiresAtEpochMillis = null,
        label = if (type == 3) displayName else null,
        isFolder = folder,
        sharedWithMe = false,
    )

    private fun sharingAccount() =
        AccountEntity(
            id = "account",
            serverUrl = "https://cloud.example",
            userId = "alice",
            displayName = "Alice",
            authenticationType = "OIDC",
            tusSupported = true,
            sharingEnabled = true,
            publicSharingEnabled = true,
            publicLinkPasswordSupported = true,
            publicLinkExpirationSupported = true,
            publicLinkExpirationDays = 30,
        )

    @Suppress("LongParameterList") // Named fixture fields make visual scenarios readable.
    private fun space(
        id: String,
        name: String,
        description: String?,
        ownerName: String,
        used: Long,
        remaining: Long,
    ) = SpaceEntity(
        accountId = "account",
        driveId = id,
        name = name,
        type = if (id == "personal") "personal" else "project",
        description = description,
        ownerName = ownerName,
        rootId = "$id-root",
        rootWebDavUrl = "https://cloud.example/dav/spaces/$id",
        rootETag = null,
        quotaBytes = used + remaining,
        quotaUsedBytes = used,
        quotaRemainingBytes = remaining,
        quotaState = "normal",
    )

    private fun snapshotPath(fileName: String) = "src/test/snapshots/rendered/$fileName.png"

    private fun failedTransfersState() =
        TransfersUiState(
            failed = listOf(transfer(TransferFixture("failed", "Budget.xlsx", TransferState.FAILED, 0, 80))),
        )

    private fun featureRoborazziOptions() =
        RoborazziOptions(
            compareOptions =
                RoborazziOptions.CompareOptions(
                    // Robolectric host anti-aliasing varies slightly; layout and color changes still fail.
                    resultValidator = { result ->
                        result.pixelDifferences.toFloat() / result.pixelCount <= 0.001f
                    },
                ),
        )

    private fun transfer(fixture: TransferFixture) =
        TransferEntity(
            id = fixture.id,
            accountId = "account",
            spaceId = "space",
            resourceId = null,
            direction = fixture.direction.name,
            sourceUri = null,
            destinationPath = "/${fixture.name}",
            displayName = fixture.name,
            mimeType = null,
            bytesTotal = fixture.total,
            bytesTransferred = fixture.transferred,
            state = fixture.state.name,
            error = fixture.error,
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )

    private data class TransferFixture(
        val id: String,
        val name: String,
        val state: TransferState,
        val transferred: Long,
        val total: Long,
        val direction: TransferDirection = TransferDirection.UPLOAD,
        val error: String? = null,
    )
}
