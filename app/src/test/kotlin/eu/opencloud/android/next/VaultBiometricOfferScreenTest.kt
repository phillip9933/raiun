package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.VaultRouteCallbacks
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

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class VaultBiometricOfferScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun passwordUnlockOfferExplainsPhoneScopeAndRoutesBothChoices() {
        var accepted = 0
        var declined = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    VaultRouteState(
                        mode = VaultRouteMode.CONTENTS,
                        selectedTitle = "Private files",
                        biometricOfferPending = true,
                    ),
                    callbacks(
                        onAcceptBiometricOffer = { accepted++ },
                        onDeclineBiometricOffer = { declined++ },
                    ),
                )
            }
        }

        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/vault_biometric_offer.png")
        compose.onNodeWithText("Unlock with biometrics?").assertExists()
        compose.onNodeWithText("This works only on this phone.", substring = true).assertExists()
        compose.onNodeWithText("Set up biometrics").performClick()
        compose.runOnIdle { assertEquals(1, accepted) }
    }

    @Test
    fun dismissingTheOfferRecordsTheDeclineCallback() {
        var declined = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    VaultRouteState(
                        mode = VaultRouteMode.CONTENTS,
                        selectedTitle = "Private files",
                        biometricOfferPending = true,
                    ),
                    callbacks(onDeclineBiometricOffer = { declined++ }),
                )
            }
        }

        compose.onNodeWithText("Not now").performClick()
        compose.runOnIdle { assertEquals(1, declined) }
    }

    private fun callbacks(
        onAcceptBiometricOffer: () -> Unit = {},
        onDeclineBiometricOffer: () -> Unit = {},
    ) = VaultRouteCallbacks(
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
        onAcceptBiometricOffer = onAcceptBiometricOffer,
        onDeclineBiometricOffer = onDeclineBiometricOffer,
    )
}
