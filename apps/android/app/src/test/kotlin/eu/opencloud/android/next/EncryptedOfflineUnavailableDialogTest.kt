package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.ui.EncryptedOfflineUnavailableDialog
import eu.opencloud.android.next.ui.dispatchOfflineAwareEncryptedLocation
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EncryptedOfflineUnavailableDialogTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun unsavedOfflineLocationShowsContextAndOnlyDismisses() {
        var dismissed = 0
        compose.setContent {
            OpenCloudTheme {
                EncryptedOfflineUnavailableDialog(location(), onDismiss = { dismissed++ })
            }
        }

        compose.onNodeWithText("Not available offline").assertExists()
        compose
            .onNodeWithText(
                "The encrypted folder “Quarterly reports” is not saved on this device and cannot be unlocked offline.",
            ).assertExists()
        compose.onNodeWithText("Close").performClick()
        assertEquals(1, dismissed)
    }

    @Test fun unsavedRootsAreInterceptedAndSavedRootsOpenNormally() {
        var opens = 0
        var unavailable = 0
        dispatchOfflineAwareEncryptedLocation(
            location(),
            onOpen = { opens++ },
            onUnavailable = { unavailable++ },
        )
        assertEquals(0, opens)
        assertEquals(1, unavailable)

        dispatchOfflineAwareEncryptedLocation(
            location().copy(offlineUnavailable = false),
            onOpen = { opens++ },
            onUnavailable = { unavailable++ },
        )
        assertEquals(1, opens)
        assertEquals(1, unavailable)
    }

    @Test fun unavailableSpaceDialogNamesTheEncryptedSpace() {
        compose.setContent {
            OpenCloudTheme {
                EncryptedOfflineUnavailableDialog(
                    location().copy(kind = VaultLocationKind.SPACE, title = "Research"),
                    onDismiss = {},
                )
            }
        }

        compose
            .onNodeWithText(
                "The encrypted Space “Research” is not saved on this device and cannot be unlocked offline.",
            ).assertExists()
    }

    private fun location() =
        VaultLocation(
            accountId = "account",
            title = "Quarterly reports",
            kind = VaultLocationKind.FOLDER_VAULT,
            driveId = "drive",
            remoteVaultId = "root-file-id",
            sourceRootId = "root-id",
            canonicalServer = "https://example.invalid",
            rootWebDavUrl = "https://example.invalid/remote.php/dav/files/user",
            vaultPath = "/Encrypted",
            isVaultRoot = true,
            offlineUnavailable = true,
        )
}
