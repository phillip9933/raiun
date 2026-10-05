package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.datastore.Appearance
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultPreferences
import eu.opencloud.android.next.feature.settings.SettingsDiagnostics
import eu.opencloud.android.next.feature.settings.SettingsScreen
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
class SettingsInteractionTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun appLockSettingsRowHasNoSecuritySubmenuNavigation() {
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(UserSettings(), {}, {}, {})
            }
        }
        compose.onNodeWithText("App lock").performScrollTo().assertExists()
        compose.onNodeWithContentDescription("Open security settings").assertDoesNotExist()
    }

    @Test fun openingPreferencesChangeOnlyTheSelectedFileType() {
        val state = mutableStateOf(UserSettings())
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(state.value, {}, {}, {}, onFileOpening = {
                    state.value =
                        state.value.copy(fileOpening = it)
                })
            }
        }
        compose.onAllNodesWithText("PDF documents").assertCountEquals(0)
        compose.onNodeWithText("Opening files").performScrollTo().performClick()
        compose.onNodeWithContentDescription("PDF documents").performScrollTo().performClick()
        compose.onNodeWithText("External app").performClick()
        assertEquals(true, state.value.fileOpening.externalPdf)
        assertEquals(false, state.value.fileOpening.externalText)
        assertEquals(false, state.value.fileOpening.externalImages)
    }

    @Test fun appearanceChoicesUpdateTheSelectedMode() {
        val state = mutableStateOf(UserSettings())
        compose.setContent {
            OpenCloudTheme(darkTheme = state.value.appearance == Appearance.DARK) {
                SettingsScreen(state.value, {}, {}, {}, onSetAppearance = {
                    state.value =
                        state.value.copy(appearance = it)
                })
            }
        }
        compose.onNodeWithText("Appearance").performClick()
        compose.onNodeWithContentDescription("Change appearance").performClick()
        compose.onNode(hasText("System") and hasAnyAncestor(isPopup())).assertIsSelected()
        compose.onNodeWithText("Dark").performClick()
        compose.onNodeWithContentDescription("Change appearance").performClick()
        compose.onNode(hasText("Dark") and hasAnyAncestor(isPopup())).assertIsSelected()
        assertEquals(Appearance.DARK, state.value.appearance)
        compose.onNodeWithText("Light").performClick()
        compose.onNodeWithContentDescription("Change appearance").performClick()
        compose.onNode(hasText("Light") and hasAnyAncestor(isPopup())).assertIsSelected()
        compose.onNodeWithText("System").performClick()
        assertEquals(Appearance.SYSTEM, state.value.appearance)
    }

    @Test fun displayOptionsAndTemporaryCleanupAreExplicit() {
        val state = mutableStateOf(UserSettings())
        var cleared = 0
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(state.value, {}, {}, {}, onFileDisplay = {
                    state.value = state.value.copy(fileDisplay = it)
                }, onClearTemporary = { cleared++ })
            }
        }
        compose.onNodeWithText("Appearance").performClick()
        compose.onNodeWithContentDescription("Hidden files").performScrollTo().performClick()
        assertEquals(true, state.value.fileDisplay.showHidden)
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Temporary local files").performScrollTo().performClick()
        compose.onNodeWithText("Clear temporary copies now").performScrollTo().performClick()
        assertEquals(0, cleared)
        compose.onNodeWithText("Cancel").performClick()
        compose.onNodeWithText("Clear temporary copies now").performClick()
        compose.onNodeWithText("Clear temporary copies").performClick()
        assertEquals(1, cleared)
    }

    @Test fun diagnosticsRequireOptIn() {
        val state = mutableStateOf(UserSettings())
        var reads = 0
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(
                    state.value,
                    {},
                    {},
                    {},
                    diagnostics =
                        SettingsDiagnostics(
                            onSetEnabled = { state.value = state.value.copy(localDiagnosticsEnabled = it) },
                            onRead = { reads++ },
                        ),
                )
            }
        }
        compose.onAllNodesWithText("View local diagnostics").assertCountEquals(0)
        compose.onNodeWithContentDescription("Local diagnostics").performScrollTo().performClick()
        compose.onNodeWithText("View local diagnostics").performScrollTo().performClick()
        assertEquals(1, reads)
        compose.onNodeWithContentDescription("Local diagnostics").performScrollTo().performClick()
        compose.onAllNodesWithText("View local diagnostics").assertCountEquals(0)
    }

    @Test fun languageMenuOffersSystemEnglishAndGerman() {
        val language = mutableStateOf("")
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(
                    UserSettings(),
                    {},
                    {},
                    {},
                    languageTag = language.value,
                    onLanguage = { language.value = it },
                )
            }
        }
        compose.onNodeWithText("Appearance").performClick()
        compose.onNodeWithContentDescription("Change language").performClick()
        compose.onNode(hasText("System default") and hasAnyAncestor(isPopup())).assertIsSelected()
        compose.onNodeWithText("Deutsch").performClick()
        assertEquals("de", language.value)
        compose.onNodeWithContentDescription("Change language").performClick()
        compose.onNode(hasText("Deutsch") and hasAnyAncestor(isPopup())).assertIsSelected()
        compose.onNodeWithText("English").performClick()
        assertEquals("en", language.value)
        compose.onNodeWithContentDescription("Change language").performClick()
        compose.onNodeWithText("System default").performClick()
        assertEquals("", language.value)
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Temporary local files").performScrollTo().performClick()
        compose.onNodeWithText("Clear temporary copies now").performScrollTo()
    }

    @Test fun cacheRetentionMenuMarksCurrentChoiceAndUpdatesValue() {
        val state = mutableStateOf(UserSettings(temporaryCopyRetentionHours = 0))
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(
                    state.value,
                    {},
                    {},
                    { state.value = state.value.copy(temporaryCopyRetentionHours = it) },
                )
            }
        }
        compose.onNodeWithText("Temporary local files").performScrollTo().performClick()
        compose.onNodeWithContentDescription("Change temporary copy retention").performScrollTo().performClick()
        compose.onNode(hasText("Never") and hasAnyAncestor(isPopup())).assertIsSelected()
        compose.onNodeWithText("1 hour").performClick()
        assertEquals(1, state.value.temporaryCopyRetentionHours)
        compose.onNodeWithContentDescription("Change temporary copy retention").performScrollTo().performClick()
        compose.onNode(hasText("1 hour") and hasAnyAncestor(isPopup())).assertIsSelected()
    }

    @Test fun dataAndSecuritySubmenusReturnToSettingsWithoutLosingActions() {
        var backups = 0
        var exits = 0
        compose.setContent {
            OpenCloudTheme {
                SettingsScreen(
                    UserSettings(),
                    onNavigateBack = { exits++ },
                    onOpenBackupSettings = { backups++ },
                    onSetRetention = {},
                    accountId = "settings-test-account",
                )
            }
        }
        compose.onNodeWithText("Data").assertExists()
        compose.onNodeWithText("Folder & camera backup").performScrollTo().performClick()
        assertEquals(1, backups)
        compose.onNodeWithText("Temporary local files").performScrollTo().performClick()
        compose.onNodeWithText("Clear temporary copies now").assertExists()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/temporary_files_settings.png")
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Encrypted preferences").performScrollTo().performClick()
        compose.waitUntil(5_000) {
            compose
                .onAllNodesWithText("No biometric choices for encrypted locations on this account.")
                .fetchSemanticsNodes()
                .isNotEmpty()
        }
        compose.onNodeWithText("No biometric choices for encrypted locations on this account.").assertExists()
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Permissions").performScrollTo().performClick()
        compose.onNodeWithText("Photo and video metadata").assertExists()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/permissions_settings.png")
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onNodeWithText("Temporary local files").assertExists()
        assertEquals(0, exits)
    }

    @Test fun encryptedChoiceShowsFolderStatusAndCancelKeepsPreference() {
        val identity =
            VaultIdentity(
                accountId = "settings-entry-test",
                canonicalServer = "https://cloud.example",
                driveId = "drive",
                remoteVaultId = "vault",
            )
        val preferences = VaultPreferences(compose.activity)
        preferences.decline(identity, "Private papers", VaultPreferenceTargetKind.FOLDER)
        try {
            compose.setContent {
                OpenCloudTheme {
                    SettingsScreen(UserSettings(), {}, {}, {}, accountId = identity.accountId)
                }
            }
            compose.onNodeWithText("Encrypted preferences").performScrollTo().performClick()
            compose.waitUntil(5_000) {
                compose.onAllNodesWithText("Private papers").fetchSemanticsNodes().isNotEmpty()
            }
            compose.onNodeWithText("Folder · cloud.example").assertExists()
            compose.onNodeWithText("Biometric offer declined").assertExists()
            compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_preferences.png")
            compose.onNodeWithText("Ask me again").performClick()
            compose.onNodeWithText("Reset biometric access?").assertExists()
            compose.onNodeWithText("Encrypted files and folders will not change.").assertExists()
            compose.onNodeWithText("Cancel").performClick()
            assertEquals(VaultPreferenceStatus.DECLINED, preferences.status(identity))
        } finally {
            preferences.remove(identity)
        }
    }
}
