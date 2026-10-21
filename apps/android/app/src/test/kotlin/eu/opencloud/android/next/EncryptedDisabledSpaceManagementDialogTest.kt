package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.ui.EncryptedDisabledSpaceActions
import eu.opencloud.android.next.ui.EncryptedDisabledSpaceManagementDialog
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
class EncryptedDisabledSpaceManagementDialogTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun purgeNeedsConfirmationAndReportsRemoval() {
        val actions = FakeActions()
        var lifecycle: VaultLocation? = location
        var closed = false
        compose.setContent {
            OpenCloudTheme {
                EncryptedDisabledSpaceManagementDialog(
                    accountId = location.accountId,
                    location = location,
                    onClose = { closed = true },
                    onLifecycleChange = { lifecycle = it },
                    actionsOverride = actions,
                )
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_disabled_space_management.png")
        compose.onNodeWithText("Permanently delete").performClick()
        compose
            .onNodeWithText(
                "Permanently delete “Encrypted Space” and all content stored in it? This cannot be undone.",
            ).assertExists()
        assertEquals(0, actions.purgeCalls)
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(0, actions.purgeCalls)
        assertEquals(false, closed)
        assertEquals(location, lifecycle)
        compose.onNodeWithText("Permanently delete").performClick()
        compose.onNodeWithText("Delete permanently").performClick()
        compose.waitUntil(5_000) { closed }
        assertEquals(1, actions.purgeCalls)
        assertEquals(null, lifecycle)
    }

    private class FakeActions : EncryptedDisabledSpaceActions {
        var purgeCalls = 0

        override suspend fun restoreDisabledSpace(
            accountId: String,
            location: VaultLocation,
        ) = location.copy(isDisabled = false)

        override suspend fun permanentlyDeleteDisabledSpace(
            accountId: String,
            location: VaultLocation,
        ) {
            purgeCalls++
        }
    }

    private companion object {
        val location =
            VaultLocation(
                accountId = "account",
                title = "Encrypted Space",
                kind = VaultLocationKind.SPACE_VAULT,
                driveId = "drive",
                remoteVaultId = "root",
                sourceRootId = "root",
                canonicalServer = "https://cloud.example/",
                rootWebDavUrl = "https://cloud.example/dav/drive",
                vaultPath = "",
                isVaultRoot = true,
                isDisabled = true,
            )
    }
}
