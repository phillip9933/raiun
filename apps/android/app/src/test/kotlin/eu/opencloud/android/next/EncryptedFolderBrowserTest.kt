package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.longClick
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.feature.files.BrowserLayout
import eu.opencloud.android.next.feature.files.FileBrowserScreen
import eu.opencloud.android.next.feature.files.FileBrowserUiState
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class EncryptedFolderBrowserTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun lockedFolderIsSortedWithFoldersAndOnlyOpensVaultWhilePlainFolderRetainsNormalBehavior() {
        val normalFolder = resource("normal", "Alpha folder")
        val lastFolder = resource("last", "Gamma folder")
        val location = vaultLocation()
        val openedVaults = mutableListOf<VaultLocation>()
        val openedResources = mutableListOf<ResourceEntity>()
        val rootMenus = mutableListOf<VaultLocation>()
        var toggles = 0
        var actions = 0
        var offlineDownloads = 0
        var selectedDownloads = 0

        compose.activity.setContent {
            OpenCloudTheme {
                FileBrowserScreen(
                    accountId = ACCOUNT,
                    releaseVersion = "test",
                    state = browserState(listOf(normalFolder, lastFolder), listOf(location)),
                    onSelectSpace = {},
                    onOpen = { openedResources += it },
                    onNavigateUp = {},
                    onSetLayout = {},
                    onToggleSelection = { toggles++ },
                    onClearSelection = {},
                    onDownloadSelection = { selectedDownloads++ },
                    onDeleteSelection = {},
                    onShowActions = { actions++ },
                    onDismissActions = {},
                    onCreateFolder = {},
                    onCreateSpace = {},
                    onRename = { _, _ -> },
                    onMove = {},
                    onCopy = {},
                    onDelete = {},
                    onUpload = {},
                    onDownloadForOffline = { offlineDownloads++ },
                    onToggleFavorite = {},
                    onResolveConflict = { _, _ -> },
                    onClearMessage = {},
                    onSearchQueryChange = {},
                    onOpenTransfers = {},
                    onOpenDeletedFiles = {},
                    onOpenSettings = {},
                    onOpenEncryptedLocation = { openedVaults += it },
                    onEncryptedLocationActions = { rootMenus += it },
                    onOpenAccount = {},
                    onShareResource = {},
                )
            }
        }

        compose.onNodeWithContentDescription("Encrypted folder, locked").assertIsDisplayed()
        val alphaTop =
            compose
                .onNodeWithText("Alpha folder")
                .fetchSemanticsNode()
                .boundsInRoot.top
        val vaultTop =
            compose
                .onNodeWithText(location.title)
                .fetchSemanticsNode()
                .boundsInRoot.top
        val gammaTop =
            compose
                .onNodeWithText("Gamma folder")
                .fetchSemanticsNode()
                .boundsInRoot.top
        assertTrue(
            "The locked folder participates in the normal folder sort",
            alphaTop < vaultTop && vaultTop < gammaTop,
        )

        compose.onNodeWithText(location.title).performClick()
        compose.runOnIdle {
            assertEquals(1, openedVaults.size)
            assertSame(location, openedVaults.single())
            assertEquals(0, openedResources.size)
            assertNoNormalEntryCallbacks(toggles, actions, offlineDownloads, selectedDownloads)
        }

        compose.onNodeWithContentDescription("Actions for ${location.title}").performClick()
        compose.runOnIdle {
            assertSame(location, rootMenus.single())
            assertEquals(0, openedResources.size)
            assertNoNormalEntryCallbacks(toggles, actions, offlineDownloads, selectedDownloads)
        }

        openedVaults.clear()
        compose.onNodeWithText(location.title).performTouchInput { longClick() }
        compose.runOnIdle {
            assertNoNormalEntryCallbacks(toggles, actions, offlineDownloads, selectedDownloads)
            // A long press may fall through to the ordinary tap; it must only reach secure entry.
            openedVaults.forEach { assertSame(location, it) }
            assertEquals(0, openedResources.size)
        }

        compose.onNodeWithText("Alpha folder").performClick()
        compose.runOnIdle { assertSame(normalFolder, openedResources.single()) }
    }

    private fun browserState(
        resources: List<ResourceEntity>,
        encryptedFolders: List<VaultLocation>,
    ) = FileBrowserUiState(
        spaces =
            listOf(
                SpaceEntity(
                    accountId = ACCOUNT,
                    driveId = DRIVE,
                    name = "Personal",
                    type = "personal",
                    description = null,
                    ownerName = null,
                    rootId = "root-id",
                    rootWebDavUrl = "https://cloud.example/dav/root",
                    rootETag = null,
                    quotaBytes = null,
                ),
            ),
        spaceId = DRIVE,
        resources = resources,
        encryptedFolders = encryptedFolders,
        layout = BrowserLayout.DEFAULT_TABLE,
    )

    private fun resource(
        id: String,
        name: String,
    ) = ResourceEntity(
        accountId = ACCOUNT,
        spaceId = DRIVE,
        remoteId = id,
        parentId = null,
        path = "/$name",
        name = name,
        kind = ResourceKind.FOLDER,
        mimeType = null,
        sizeBytes = 0,
        eTag = null,
        modifiedAtEpochMillis = 0,
        createdAtEpochMillis = 0,
    )

    private fun vaultLocation() =
        VaultLocation(
            accountId = ACCOUNT,
            title = "Beta locked vault",
            kind = VaultLocationKind.FOLDER_VAULT,
            driveId = DRIVE,
            remoteVaultId = "vault-root-id",
            sourceRootId = "root-id",
            canonicalServer = "https://cloud.example",
            rootWebDavUrl = "https://cloud.example/dav/root",
            vaultPath = ".vault",
            isVaultRoot = true,
        )

    private fun assertNoNormalEntryCallbacks(
        toggles: Int,
        actions: Int,
        offlineDownloads: Int,
        selectedDownloads: Int,
    ) {
        assertEquals(0, toggles)
        assertEquals(0, actions)
        assertEquals(0, offlineDownloads)
        assertEquals(0, selectedDownloads)
    }

    private companion object {
        const val ACCOUNT = "browser-account"
        const val DRIVE = "personal-drive"
    }
}
