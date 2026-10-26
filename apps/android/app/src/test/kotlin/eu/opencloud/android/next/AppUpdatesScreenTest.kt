package eu.opencloud.android.next

import android.app.Application
import androidx.activity.ComponentActivity
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.settings.AppUpdatesScreen
import eu.opencloud.android.next.feature.settings.RaiunUpdates
import eu.opencloud.android.next.feature.settings.SettingsScreen
import eu.opencloud.android.next.feature.settings.UpdateActions
import io.github.phillip9933.appupdater.AndroidUpdateChannel
import io.github.phillip9933.appupdater.AndroidUpdateRelease
import io.github.phillip9933.appupdater.UpdateError
import io.github.phillip9933.appupdater.UpdateState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp", application = Application::class)
class AppUpdatesScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun stableAndBetaSelectionAndManualCheckAreExplicit() {
        var selected: AndroidUpdateChannel? = null
        var checks = 0
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(installedVersion = "1.0.0"),
                    {},
                    UpdateActions(onChannel = { selected = it }, onCheck = { checks++ }),
                )
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/app_updates_settings.png")
        compose.onNodeWithText("Stable and beta").performClick()
        assertEquals(AndroidUpdateChannel.BETA, selected)
        compose.onNodeWithText("Check now").performScrollTo().performClick()
        assertEquals(1, checks)
    }

    @Test fun busyDownloadCanBeCancelledAndCannotStartAnotherCheck() {
        var cancellations = 0
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(
                        installedVersion = "1.0.0",
                        available = release(),
                        downloading = true,
                        bytesDownloaded = 50,
                    ),
                    {},
                    UpdateActions(onCancel = { cancellations++ }),
                )
            }
        }
        compose.onNodeWithText("Check now").performScrollTo().assertIsNotEnabled()
        compose.onNodeWithText("Downloading update… 50%").performScrollTo().assertExists()
        compose.onNodeWithText("Cancel download").performScrollTo().performClick()
        assertEquals(1, cancellations)
    }

    @Test fun readyReleaseShowsInstallAction() {
        var installs = 0
        compose.setContent {
            OpenCloudTheme(darkTheme = true) {
                AppUpdatesScreen(
                    UpdateState(installedVersion = "1.0.0", available = release(), ready = true),
                    {},
                    UpdateActions(),
                    installControl = { Button(onClick = { installs++ }) { Text("Install update") } },
                )
            }
        }
        compose.onNodeWithText("Install update").performScrollTo().performClick()
        assertEquals(1, installs)
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/app_update_release_dark.png")
    }

    @Test fun failedCheckNeverSaysUpToDate() {
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(
                        installedVersion = "1.0.0",
                        lastChecked = 1,
                        error = UpdateError.NETWORK,
                    ),
                    {
                    },
                    UpdateActions(),
                )
            }
        }
        compose
            .onNodeWithText(
                "Could not check for updates. Check your connection or try again later.",
            ).performScrollTo()
            .assertExists()
        compose.onNodeWithText("No newer compatible Android release was found.").assertDoesNotExist()
    }

    @Test fun mismatchedSigningKeyNeverOffersInstall() {
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(
                        installedVersion = "1.0.0",
                        available = release(),
                        error = UpdateError.SIGNATURE_MISMATCH,
                    ),
                    {},
                    UpdateActions(),
                )
            }
        }
        compose
            .onNodeWithText(
                "This update uses a different signing key and cannot update this installation. Keep the current app installed to preserve your data.",
            ).performScrollTo()
            .assertExists()
        compose.onNodeWithText("Install update").assertDoesNotExist()
    }

    @Test fun updateSettingsAreReachableAndBackReturnsToSettings() {
        compose.setContent { OpenCloudTheme { SettingsScreen(UserSettings(), {}, {}, {}) } }
        compose.onNodeWithText("App updates").performScrollTo().performClick()
        compose.onNodeWithText("Check now").performScrollTo().assertExists()
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Settings").assertExists()
    }

    @Test fun installedReleaseAndProjectLinksUseFixedGitHubDestinations() {
        val opened = mutableListOf<String>()
        compose.setContent {
            OpenCloudTheme {
                AppUpdatesScreen(
                    UpdateState(installedVersion = "1.0.0-debug"),
                    {},
                    UpdateActions(onOpenLink = { opened += it }),
                )
            }
        }
        compose.onNodeWithText("GitHub project").performScrollTo().performClick()
        compose.onNodeWithText("Installed release").performScrollTo().performClick()
        assertEquals(
            listOf(
                "https://github.com/phillip9933/raiun",
                "https://github.com/phillip9933/raiun/releases/tag/android-v1.0.0",
            ),
            opened,
        )
        assertEquals(null, RaiunUpdates.installedReleaseUrl("1.0.0/path"))
        assertEquals(
            "https://github.com/phillip9933/raiun/releases/tag/v0.9.3",
            RaiunUpdates.installedReleaseUrl("0.9.3"),
        )
    }

    @Test fun directUpdatesEntryReturnsToSettingsOnBack() {
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(UserSettings(), {}, {}, {}, openUpdatesInitially = true)
            }
        }
        compose.onNodeWithText("Check now").performScrollTo().assertExists()
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Settings").assertExists()
    }

    private fun release() =
        AndroidUpdateRelease(
            "android-v1.0.1",
            "A safer update experience.",
            "raiun-android-1.0.1.apk",
            "https://github.com/phillip9933/raiun/releases/download/android-v1.0.1/raiun-android-1.0.1.apk",
            100,
            null,
            null,
        )
}
