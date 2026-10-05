package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.VaultLocationKindUi
import eu.opencloud.android.next.ui.VaultRouteCallbacks
import eu.opencloud.android.next.ui.VaultRouteLocation
import eu.opencloud.android.next.ui.VaultRouteMode
import eu.opencloud.android.next.ui.VaultRouteState
import eu.opencloud.android.next.ui.VaultScreen
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
class EncryptedRootMenuTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    // Rename text entry is covered by EncryptedRootRenameInstrumentedTest on Android.
    // Robolectric API 35 repeatedly fails to settle this secure dialog's text-field layout.

    @Test fun folderRootDeleteRequiresExplicitConfirmation() {
        var deleted = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(folderRoot(), callbacks().copy(onDeleteRoot = { deleted++ }))
            }
        }
        compose.onNodeWithText("Delete").performClick()
        val warning =
            "Delete “Private”? Only an empty encrypted folder can be deleted here. " +
                "Remove or move its contents first."
        compose.onNodeWithText(warning).assertExists()
        assertEquals(0, deleted)
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(0, deleted)
        compose.onNodeWithText("Delete").performClick()
        compose.onAllNodesWithText("Delete")[1].performClick()
        assertEquals(1, deleted)
    }

    @Test fun spaceRootRoutesManagementWithoutRawDavActions() {
        compose.setContent { OpenCloudTheme { VaultScreen(spaceRoot(), callbacks()) } }
        compose.onNodeWithText("Rename").assertDoesNotExist()
        compose.onNodeWithText("Delete").assertDoesNotExist()
        compose.onNodeWithText("Manage Space").assertExists()
    }

    private fun folderRoot() =
        VaultRouteState(
            mode = VaultRouteMode.CONTENTS,
            selectedLocation = VaultRouteLocation("folder", "Private", VaultLocationKindUi.FOLDER_VAULT, true),
            selectedTitle = "Private",
            rootActionsVisible = true,
        )

    private fun spaceRoot() =
        VaultRouteState(
            mode = VaultRouteMode.CONTENTS,
            selectedLocation = VaultRouteLocation("space", "Secure Space", VaultLocationKindUi.SPACE_VAULT, true),
            selectedTitle = "Secure Space",
            rootActionsVisible = true,
        )

    private fun callbacks() =
        VaultRouteCallbacks(
            onNavigateBack = {},
            onSelectLocation = {},
            onOpenDiscoveryFolder = {},
            onSelectVaultFolder = {},
            onUnlock = {},
            onBiometricUnlock = {},
            onBiometricEnroll = {},
            onForgetBiometric = {},
            onOpenVaultFolder = {},
            onOpenPreview = {},
            onDismissPreview = {},
            onUp = {},
            onLock = {},
            onRetry = {},
            onDismissRootActions = {},
            onRenameRoot = {},
            onDeleteRoot = {},
        )
}
