package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.VaultEntryAction
import eu.opencloud.android.next.ui.VaultLocationKindUi
import eu.opencloud.android.next.ui.VaultRouteCallbacks
import eu.opencloud.android.next.ui.VaultRouteError
import eu.opencloud.android.next.ui.VaultRouteLocation
import eu.opencloud.android.next.ui.VaultRouteMode
import eu.opencloud.android.next.ui.VaultRouteState
import eu.opencloud.android.next.ui.VaultScreen
import eu.opencloud.android.next.ui.VaultTransferConflict
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
class VaultScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun catalogFailureDoesNotAlsoReportThatNoVaultsExist() {
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(VaultRouteState(error = VaultRouteError.CATALOG), callbacks())
            }
        }

        compose.onNodeWithText("Vaults could not be loaded. Try again.").assertExists()
        compose.onNodeWithText("No encrypted vaults were found.").assertDoesNotExist()
        compose.onNodeWithText("Try again").assertExists()
    }

    @Test fun unreadableServerVaultResponseShowsDiagnosticCopyWithoutEmptyState() {
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(VaultRouteState(error = VaultRouteError.SERVER_RESPONSE), callbacks())
            }
        }

        compose
            .onNodeWithText(
                "The server returned vault information Raiun could not read. Try again or report this problem.",
            ).assertExists()
        compose.onNodeWithText("No encrypted vaults were found.").assertDoesNotExist()
    }

    @Test fun successfulEmptyCatalogStillReportsNoVaults() {
        compose.setContent { OpenCloudTheme { VaultScreen(VaultRouteState(), callbacks()) } }

        compose.onNodeWithText("No encrypted vaults were found.").assertExists()
    }

    @Test fun transferConflictShowsProposedNumberedNameAndKeepBothResolution() {
        var keepBoth: Boolean? = null
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    VaultRouteState(
                        mode = VaultRouteMode.CONTENTS,
                        transferConflict = transferConflict(),
                    ),
                    callbacks(onResolveTransferConflict = { keepBoth = it }),
                )
            }
        }

        compose.onNodeWithText("An item with this name already exists").assertExists()
        compose
            .onNodeWithText(
                "report.pdf already exists in this folder. Keep both using the name report (1).pdf, or cancel.",
            ).assertExists()
        compose.onNodeWithText("Keep both").performClick()
        compose.runOnIdle { assertEquals(true, keepBoth) }
    }

    @Test fun transferConflictCancelRejectsTheProposalWithoutNameInput() {
        var keepBoth: Boolean? = null
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    VaultRouteState(
                        mode = VaultRouteMode.CONTENTS,
                        transferConflict = transferConflict(),
                    ),
                    callbacks(onResolveTransferConflict = { keepBoth = it }),
                )
            }
        }

        compose.onAllNodes(hasSetTextAction()).assertCountEquals(0)
        compose.onNodeWithText("Cancel").performClick()
        compose.runOnIdle { assertEquals(false, keepBoth) }
    }

    @Test fun discoveryFailureDoesNotAlsoReportThatNoVaultsExist() {
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    VaultRouteState(mode = VaultRouteMode.DISCOVERY, error = VaultRouteError.DISCOVERY),
                    callbacks(),
                )
            }
        }

        compose.onNodeWithText("Folders could not be loaded. Try again.").assertExists()
        compose.onNodeWithText("No folders or vaults were found here.").assertDoesNotExist()
    }

    @Test fun successfulEmptyDiscoveryStillReportsNoFolders() {
        compose.setContent {
            OpenCloudTheme { VaultScreen(VaultRouteState(mode = VaultRouteMode.DISCOVERY), callbacks()) }
        }

        compose.onNodeWithText("No folders or vaults were found here.").assertExists()
    }

    @Test fun passwordIsClearedAfterSubmissionAndAfterLockWhileAlreadyLocked() {
        val state = mutableStateOf(unlockState())
        var submitted: String? = null
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks(onUnlock = {
                        submitted = String(it)
                        it.fill('\u0000')
                    }),
                )
            }
        }
        compose.onNodeWithText("Unlock").assertIsNotEnabled()
        compose.onNodeWithText("Vault password").performTextInput("synthetic-vault-password")
        compose.onNodeWithText("Unlock").assertIsEnabled().performClick()
        assertEquals("synthetic-vault-password", submitted)
        compose.onNodeWithText("Unlock").assertIsNotEnabled()
        compose.onNodeWithText("Vault password").performTextInput("another-synthetic-password")
        compose.runOnIdle { state.value = state.value.copy(lockRevision = state.value.lockRevision + 1) }
        compose.onNodeWithText("Unlock").assertIsNotEnabled()
    }

    @Test fun passwordVisibilityReturnsToHiddenAfterSubmissionAndLock() {
        val state = mutableStateOf(unlockState())
        compose.setContent { OpenCloudTheme { VaultScreen(state.value, callbacks()) } }
        compose.onNodeWithText("Vault password").performTextInput("synthetic-only")
        compose.onNodeWithContentDescription("Show password").performClick()
        compose.onNodeWithContentDescription("Hide password").assertExists()
        compose.onNodeWithText("Unlock").performClick()
        compose.onNodeWithContentDescription("Show password").assertExists()
        compose.onNodeWithContentDescription("Show password").performClick()
        compose.runOnIdle { state.value = state.value.copy(lockRevision = state.value.lockRevision + 1) }
        compose.onNodeWithContentDescription("Show password").assertExists()
        compose.onNodeWithText("Unlock").assertIsNotEnabled()
    }

    @Test fun unlockScreenDoesNotOfferBiometricsWithoutAnEnrollment() {
        compose.setContent { OpenCloudTheme { VaultScreen(unlockState(), callbacks()) } }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/vault_unlock.png")
        compose.onNodeWithText("Use biometrics on this phone").assertDoesNotExist()
        compose.onNodeWithText("Vault password").assertExists()
    }

    @Test fun forgettingBiometricAccessRequiresExplicitConfirmation() {
        var forgetCount = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(unlockState().copy(biometricEnrolled = true), callbacks(onForget = { forgetCount++ }))
            }
        }
        compose.onNodeWithText("Forget biometric access").performClick()
        compose.onNodeWithText("Remove biometric access?").assertExists()
        compose
            .onNodeWithText(
                "You’ll need this vault’s password to unlock it again on this phone. Keep your password available.",
            ).assertExists()
        compose.runOnIdle { assertEquals(0, forgetCount) }
        compose.onNodeWithText("Keep access").performClick()
        compose.onNodeWithText("Remove biometric access?").assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, forgetCount) }
        compose.onNodeWithText("Forget biometric access").performClick()
        compose.onNodeWithText("Remove access").performClick()
        compose.runOnIdle { assertEquals(1, forgetCount) }
    }

    @Test fun forgetConfirmationClosesOnLockAndTargetChange() {
        val state = mutableStateOf(unlockState().copy(biometricEnrolled = true))
        var forgetCount = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(state.value, callbacks(onForget = { forgetCount++ }))
            }
        }
        compose.onNodeWithText("Forget biometric access").performClick()
        compose.runOnIdle { state.value = state.value.copy(lockRevision = state.value.lockRevision + 1) }
        compose.onNodeWithText("Remove biometric access?").assertDoesNotExist()
        compose.onNodeWithText("Forget biometric access").performClick()
        compose.runOnIdle { state.value = state.value.copy(selectedTitle = "Another vault") }
        compose.onNodeWithText("Remove biometric access?").assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, forgetCount) }
    }

    @Test
    @Config(qualifiers = "w320dp-h600dp")
    fun narrowUnlockStillExposesBiometricActions() {
        compose.setContent { OpenCloudTheme { VaultScreen(unlockState().copy(biometricEnrolled = true), callbacks()) } }
        compose.onNodeWithText("Unlock with biometrics").assertExists()
        compose.onNodeWithText("Forget biometric access").assertExists().performClick()
        compose.onNodeWithText("Keep access").performClick()
    }

    private fun unlockState() =
        VaultRouteState(
            mode = VaultRouteMode.UNLOCK,
            selectedLocation =
                VaultRouteLocation(
                    "synthetic-vault",
                    "Travel documents",
                    VaultLocationKindUi.FOLDER_VAULT,
                    true,
                ),
            selectedTitle = "Travel documents",
        )

    private fun callbacks(
        onUnlock: (CharArray) -> Unit = {},
        onForget: () -> Unit = {},
        onResolveTransferConflict: (Boolean) -> Unit = {},
    ) = VaultRouteCallbacks(
        onNavigateBack = {},
        onSelectLocation = {},
        onOpenDiscoveryFolder = {},
        onSelectVaultFolder = {},
        onUnlock = onUnlock,
        onBiometricUnlock = {},
        onBiometricEnroll = {},
        onForgetBiometric = onForget,
        onOpenVaultFolder = {},
        onOpenPreview = {},
        onDismissPreview = {},
        onUp = {},
        onLock = {},
        onRetry = {},
        onResolveTransferConflict = onResolveTransferConflict,
    )

    private fun transferConflict() =
        VaultTransferConflict(
            sourceId = "synthetic-entry",
            name = "report.pdf",
            path = "",
            action = VaultEntryAction.COPY,
            proposedName = "report (1).pdf",
        )
}
