package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasProgressBarRangeInfo
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.VaultLocationKindUi
import eu.opencloud.android.next.ui.VaultRouteCallbacks
import eu.opencloud.android.next.ui.VaultRouteLocation
import eu.opencloud.android.next.ui.VaultRouteMode
import eu.opencloud.android.next.ui.VaultRouteState
import eu.opencloud.android.next.ui.VaultScreen
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class VaultUnlockWaitingScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun busyUnlockShowsNeutralAccessibleWaitWithoutPasswordOrBiometricControls() {
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(unlockState(loading = true, phoneSessionIssueCode = "US7"), callbacks())
            }
        }

        compose.onNodeWithText("Verifying key…").assertIsDisplayed()
        compose.onNode(hasProgressBarRangeInfo(ProgressBarRangeInfo.Indeterminate)).assertExists()
        compose.onNodeWithContentDescription("Back").assertExists()
        compose.onNodeWithText("Vault password").assertDoesNotExist()
        compose.onNodeWithText("Unlock").assertDoesNotExist()
        compose.onNodeWithText("Unlock with biometrics").assertDoesNotExist()
        compose.onNodeWithText("Forget biometric access").assertDoesNotExist()
        compose.onNodeWithText("Phone-session reuse needs attention (code US7).", substring = true).assertDoesNotExist()
    }

    @Test
    fun idleUnlockRetainsPasswordAndBiometricControlsAndShowsOpaqueIssueCode() {
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(unlockState(loading = false, phoneSessionIssueCode = "US5"), callbacks())
            }
        }

        compose.onNodeWithText("Verifying key…").assertDoesNotExist()
        compose.onNodeWithText("Vault password").assertIsDisplayed()
        compose.onNodeWithText("Unlock").assertIsDisplayed()
        compose.onNodeWithText("Unlock with biometrics").assertIsDisplayed()
        compose.onNodeWithText("Forget biometric access").assertIsDisplayed()
        compose.onNodeWithText("Phone-session reuse needs attention (code US5).", substring = true).assertIsDisplayed()
    }

    private fun unlockState(
        loading: Boolean,
        phoneSessionIssueCode: String,
    ) = VaultRouteState(
        mode = VaultRouteMode.UNLOCK,
        selectedLocation = VaultRouteLocation("vault", "Test vault", VaultLocationKindUi.FOLDER_VAULT, true),
        selectedTitle = "Test vault",
        loading = loading,
        biometricEnrolled = true,
        phoneSessionIssueCode = phoneSessionIssueCode,
    )

    private fun callbacks() =
        VaultRouteCallbacks(
            onNavigateBack = {},
            onSelectLocation = {},
            onOpenDiscoveryFolder = {},
            onSelectVaultFolder = {},
            onUnlock = { it.fill('\u0000') },
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
