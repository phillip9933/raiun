package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
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

/** Exercises the secure root action dialog on Android without network or vault-key dependencies. */
@RunWith(AndroidJUnit4::class)
class EncryptedRootRenameInstrumentedTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun renameRootRequiresConfirmationAndSubmitsEditedName() {
        var renamed: String? = null
        val state =
            VaultRouteState(
                mode = VaultRouteMode.CONTENTS,
                selectedLocation =
                    VaultRouteLocation("synthetic-root", "Private", VaultLocationKindUi.FOLDER_VAULT, true),
                selectedTitle = "Private",
                rootActionsVisible = true,
            )
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(state, callbacks().copy(onRenameRoot = { renamed = it }))
            }
        }

        compose.onNodeWithText("Rename").performClick()
        compose.runOnIdle { assertEquals(null, renamed) }
        compose.onNode(hasSetTextAction()).performTextClearance()
        compose.onNode(hasSetTextAction()).performTextInput("Private archive")
        compose.onNodeWithText("Confirm").performClick()
        compose.runOnIdle { assertEquals("Private archive", renamed) }
    }

    @Test fun createFolderDialogCancelAndConfirmSubmitOnlyTheConfirmedName() {
        var created: String? = null
        val state =
            VaultRouteState(
                mode = VaultRouteMode.CONTENTS,
                selectedLocation =
                    VaultRouteLocation(
                        "synthetic-root",
                        "Private",
                        VaultLocationKindUi.FOLDER_VAULT,
                        true,
                    ),
                selectedTitle = "Private",
            )
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(state, callbacks().copy(onCreateFolder = { created = it }))
            }
        }

        compose.onNodeWithContentDescription("New actions").performClick()
        compose.onNodeWithContentDescription("New folder").performClick()
        compose.onNodeWithText("Cancel").performClick()
        compose.runOnIdle { assertEquals(null, created) }

        compose.onNodeWithContentDescription("New actions").performClick()
        compose.onNodeWithContentDescription("New folder").performClick()
        compose.onNode(hasSetTextAction()).performTextInput("Quarterly records")
        compose.onNodeWithText("Confirm").performClick()
        compose.runOnIdle { assertEquals("Quarterly records", created) }
    }

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
        )
}
