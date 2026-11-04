package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.VaultDirectoryPageState
import eu.opencloud.android.next.ui.VaultEntryAction
import eu.opencloud.android.next.ui.VaultLocationKindUi
import eu.opencloud.android.next.ui.VaultRouteCallbacks
import eu.opencloud.android.next.ui.VaultRouteEntry
import eu.opencloud.android.next.ui.VaultRouteError
import eu.opencloud.android.next.ui.VaultRouteLocation
import eu.opencloud.android.next.ui.VaultRouteMode
import eu.opencloud.android.next.ui.VaultRouteState
import eu.opencloud.android.next.ui.VaultScreen
import eu.opencloud.android.next.ui.VaultTransferConflict
import eu.opencloud.android.next.ui.rememberVaultUploadSnackbar
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import eu.opencloud.android.next.feature.settings.R as SettingsR

@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class VaultScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun queuedUploadNoticeDoesNotReplayWhenScannerReturnsAndNewJobsStillNotify() {
        val scanning = mutableStateOf(false)
        val queuedCount = mutableLongStateOf(0L)
        var snackbar: SnackbarHostState? = null
        val message = compose.activity.getString(R.string.vault_background_upload_queued)
        compose.setContent {
            OpenCloudTheme {
                val uploadSnackbar = rememberVaultUploadSnackbar(queuedCount.value, !scanning.value)
                snackbar = uploadSnackbar
                if (!scanning.value) {
                    VaultScreen(VaultRouteState(), callbacks(), uploadSnackbar = uploadSnackbar)
                }
            }
        }
        compose.onNodeWithText(message).assertDoesNotExist()
        compose.runOnIdle { queuedCount.value = 1 }
        compose.onNodeWithText(message).assertExists()
        compose.runOnIdle { requireNotNull(snackbar).currentSnackbarData?.dismiss() }
        compose.onNodeWithText(message).assertDoesNotExist()

        compose.runOnIdle { scanning.value = true }
        compose.waitForIdle()
        compose.runOnIdle { queuedCount.value = 2 }
        compose.runOnIdle { assertEquals(null, requireNotNull(snackbar).currentSnackbarData) }
        compose.runOnIdle { scanning.value = false }
        compose.onNodeWithText(message).assertExists()
        compose.runOnIdle { requireNotNull(snackbar).currentSnackbarData?.dismiss() }
        compose.runOnIdle { scanning.value = true }
        compose.runOnIdle { scanning.value = false }
        compose.onNodeWithText(message).assertDoesNotExist()
        compose.runOnIdle { queuedCount.value = 3 }
        compose.onNodeWithText(message).assertExists()
    }

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

    @Test fun firstRememberPromptUsesDirectPhoneRememberAction() {
        var rememberCalls = 0
        var biometricCalls = 0
        val message = compose.activity.getString(R.string.vault_phone_remember_offer_message)
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    unlockState().copy(biometricOfferPending = true, phoneRememberOffer = true),
                    callbacks(
                        promptActions =
                            VaultScreenPromptActions(
                                onRemember = { rememberCalls++ },
                                onAcceptBiometric = { biometricCalls++ },
                            ),
                    ),
                )
            }
        }
        compose.onNodeWithText("Remember on this phone?").assertExists()
        compose.onNodeWithText(message).assertExists()
        compose.onNodeWithText("Remember on this phone").assertExists().performClick()
        compose.runOnIdle {
            assertEquals(1, rememberCalls)
            assertEquals(0, biometricCalls)
        }
    }

    @Test fun existingBiometricOfferKeepsItsSeparatePerUseAction() {
        var biometricCalls = 0
        var rememberCalls = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    unlockState().copy(biometricOfferPending = true),
                    callbacks(
                        promptActions =
                            VaultScreenPromptActions(
                                onRemember = { rememberCalls++ },
                                onAcceptBiometric = { biometricCalls++ },
                            ),
                    ),
                )
            }
        }
        compose.onNodeWithText("Unlock with biometrics?").assertExists()
        compose.onNodeWithText("Set up biometrics").assertExists().performClick()
        compose.runOnIdle {
            assertEquals(1, biometricCalls)
            assertEquals(0, rememberCalls)
        }
    }

    @Test fun phoneRememberDeclineIsExplicitAskEveryTimeChoice() {
        var declineCalls = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    unlockState().copy(biometricOfferPending = true, phoneRememberOffer = true),
                    callbacks(
                        promptActions = VaultScreenPromptActions(onDeclineBiometric = { declineCalls++ }),
                    ),
                )
            }
        }
        compose.onNodeWithText("Ask every time").assertExists().performClick()
        compose.runOnIdle { assertEquals(1, declineCalls) }
    }

    @Test fun askEveryTimeDescriptionStatesUnsupportedDeviceFallback() {
        val explanation = compose.activity.getString(SettingsR.string.settings_encrypted_unlock_session_explanation)
        assertTrue(explanation.contains("Unsupported devices"))
        assertTrue(explanation.contains("fresh authentication"))
        assertTrue(explanation.contains("Raiun restarts"))
    }

    @Test fun explicitPhoneLockShowsPendingStatusInsteadOfGenericVerification() {
        val state = mutableStateOf(unlockState().copy(loading = true, lockingRememberedAccess = true))
        compose.setContent {
            OpenCloudTheme { VaultScreen(state.value, callbacks()) }
        }
        compose.onNodeWithText("Locking remembered access…").assertExists()
        compose.onNodeWithText("Verifying key…").assertDoesNotExist()
        compose.runOnIdle {
            state.value = unlockState().copy(error = VaultRouteError.PHONE_LOCK_FAILED)
        }
        compose.onNodeWithText(compose.activity.getString(R.string.vault_phone_lock_failed)).assertExists()
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

    @Test fun encryptedPagingShowsGlobalCountAndRoutesPreviousAndNextWithoutResortingPage() {
        val requests = mutableListOf<Boolean>()
        val state =
            mutableStateOf(
                unlockState().copy(
                    mode = VaultRouteMode.CONTENTS,
                    directoryPage = VaultDirectoryPageState(37, 301, 2, true),
                    entries =
                        listOf(
                            VaultRouteEntry("z", "z-first-from-snapshot", "z", false, false, 1, "text/plain"),
                            VaultRouteEntry("a", "a-second-from-snapshot", "a", false, false, 1, "text/plain"),
                        ),
                ),
            )
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(onDirectoryPage = {
                        requests +=
                            it
                    }),
                )
            }
        }
        compose.onNodeWithText("38–39 of 301").assertExists()
        compose.onNodeWithText("Previous").performClick()
        compose.onNodeWithText("Next").performClick()
        compose.runOnIdle {
            assertEquals(listOf(true, false), requests)
            state.value = state.value.copy(loading = true)
        }
        compose.onNodeWithText("Previous").assertIsNotEnabled()
        compose.onNodeWithText("Next").assertIsNotEnabled()
    }

    @Test
    @Config(qualifiers = "w320dp-h800dp")
    fun largeFontEncryptedPagingKeepsBothButtonsAndFabReachable() {
        val requests = mutableListOf<Boolean>()
        val state =
            unlockState().copy(
                mode = VaultRouteMode.CONTENTS,
                directoryPage = VaultDirectoryPageState(8_999_999_744, 9_000_000_000, 1, true),
                entries = listOf(VaultRouteEntry("row", "large-inventory", "row", false, false, 1, "text/plain")),
            )
        compose.setContent {
            CompositionLocalProvider(LocalDensity provides Density(LocalDensity.current.density, 2f)) {
                OpenCloudTheme { VaultScreen(state, callbacks().copy(onDirectoryPage = { requests += it })) }
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
        promptActions: VaultScreenPromptActions = VaultScreenPromptActions(),
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
        onRememberOnPhone = promptActions.onRemember,
        onAcceptBiometricOffer = promptActions.onAcceptBiometric,
        onDeclineBiometricOffer = promptActions.onDeclineBiometric,
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

private data class VaultScreenPromptActions(
    val onRemember: () -> Unit = {},
    val onAcceptBiometric: () -> Unit = {},
    val onDeclineBiometric: () -> Unit = {},
)
