package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.RemoteShare
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.ui.EncryptedFolderSharingDialog
import eu.opencloud.android.next.ui.FolderShareBackend
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
class EncryptedFolderSharingDialogTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun compactDialogShowsOnlyNamedRootCollaborators() {
        val backend = FakeBackend()
        showDialog(backend)
        waitForCollaborator()

        compose.onNodeWithText("Collaborators").assertExists()
        compose.onNodeWithText("Avery Reader").assertExists()
        compose.onNodeWithText("Public link").assertDoesNotExist()
        compose.onNodeWithText("Child folder").assertDoesNotExist()
        compose.onNodeWithText("They still need the encryption password", substring = true).assertExists()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_folder_sharing.png")
    }

    @Test
    fun removingAccessRequiresConfirmation() {
        val backend = FakeBackend()
        showDialog(backend)
        waitForCollaborator()

        compose.onNodeWithText("Avery Reader").performClick()
        compose.onNodeWithText("Remove access").performClick()
        compose.onNodeWithText("Remove this collaborator’s access", substring = true).assertExists()
        assertEquals(0, backend.removeCalls)
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_folder_share_remove.png")
        compose.onNodeWithText("Remove access").performClick()
        compose.waitUntil(5_000) { backend.removeCalls == 1 }
    }

    @Test
    fun unknownPermissionsAreNeverGrantedByDefault() {
        showDialog(FakeBackend(permissions = 5))
        waitForCollaborator()

        compose.onNodeWithText("Avery Reader").performClick()
        compose.onNodeWithText("This share has custom permissions", substring = true).assertExists()
        compose.onNodeWithText("Save").assertIsNotEnabled()
    }

    @Test
    fun revokedAccessInvalidatesParentSession() {
        val backend = FakeBackend(updateFailure = OpenCloudError.AccessDenied)
        var invalidations = 0
        showDialog(backend) { invalidations++ }
        waitForCollaborator()

        compose.onNodeWithText("Avery Reader").performClick()
        compose.onNodeWithText("Edit contents").performClick()
        compose.onNodeWithText("Save").performClick()
        compose.waitUntil(5_000) { invalidations == 1 }
        assertEquals(1, backend.updateCalls)
    }

    private fun showDialog(
        backend: FakeBackend,
        onInvalidate: () -> Unit = {},
    ) {
        compose.setContent {
            OpenCloudTheme {
                EncryptedFolderSharingDialog(
                    accountId = ACCOUNT_ID,
                    location = location,
                    isUnlocked = { true },
                    onClose = {},
                    onInvalidate = onInvalidate,
                    backend = backend,
                )
            }
        }
    }

    private fun waitForCollaborator() {
        compose.waitUntil(5_000) { compose.onAllNodesWithText("Avery Reader").fetchSemanticsNodes().isNotEmpty() }
    }

    private class FakeBackend(
        permissions: Int = 1,
        private val updateFailure: OpenCloudError? = null,
    ) : FolderShareBackend {
        private var shares =
            listOf(
                share(permissions),
                share(1, type = OcsShareType.PUBLIC_LINK, id = "public", name = "Public link"),
                share(1, id = "child", resourceId = "child-id", name = "Child folder"),
            )
        var removeCalls = 0
        var updateCalls = 0

        override suspend fun list(
            accountId: String,
            location: VaultLocation,
            isUnlocked: () -> Boolean,
        ) = shares

        override suspend fun search(
            accountId: String,
            location: VaultLocation,
            query: String,
            isUnlocked: () -> Boolean,
        ): List<ShareRecipient> = emptyList()

        override suspend fun add(
            accountId: String,
            location: VaultLocation,
            recipient: ShareRecipient,
            permissions: Int,
            isUnlocked: () -> Boolean,
        ) = Unit

        override suspend fun update(
            accountId: String,
            location: VaultLocation,
            shareId: String,
            permissions: Int,
            isUnlocked: () -> Boolean,
        ) {
            updateCalls++
            updateFailure?.let { throw OpenCloudException(it) }
            shares = listOf(share(permissions))
        }

        override suspend fun remove(
            accountId: String,
            location: VaultLocation,
            shareId: String,
            isUnlocked: () -> Boolean,
        ) {
            removeCalls++
            shares = emptyList()
        }
    }

    private companion object {
        const val ACCOUNT_ID = "folder-share-dialog-test"
        val location =
            VaultLocation(
                accountId = ACCOUNT_ID,
                title = "Secure team folder",
                kind = VaultLocationKind.FOLDER_VAULT,
                driveId = "personal-drive",
                remoteVaultId = "folder-root",
                sourceRootId = "graph-root",
                canonicalServer = "https://cloud.example",
                rootWebDavUrl = "https://cloud.example/dav/root",
                vaultPath = "Secure team folder",
                isVaultRoot = true,
            )

        fun share(
            permissions: Int,
            type: OcsShareType = OcsShareType.USER,
            id: String = "share-1",
            resourceId: String = "folder-root",
            name: String = "Avery Reader",
        ) = RemoteShare(
            id = id,
            type = type,
            path = "/Secure team folder",
            resourceId = resourceId,
            shareWith = "avery",
            displayName = name,
            additionalInfo = null,
            permissions = permissions,
            sharedAtEpochSeconds = 0,
            expiresAtEpochMillis = null,
            label = null,
            isFolder = true,
            publicUrl = null,
        )
    }
}
