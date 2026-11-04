package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.isToggleable
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class BrowserCreationDialogTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun plainCreationNeverCallsEncryptedCallback() {
        var plainName: String? = null
        var encryptedCalls = 0
        compose.setContent {
            OpenCloudTheme {
                BrowserCreationDialog(
                    title = "New folder",
                    encryptLabel = "Encrypt folder",
                    onPlainCreate = { plainName = it },
                    onEncryptedCreate = { _, _ -> encryptedCalls++ },
                    onDismiss = {},
                )
            }
        }
        compose.onNodeWithText("Name").performTextInput("Documents")
        compose.onNodeWithText("Create").performClick()
        assertEquals("Documents", plainName)
        assertEquals(0, encryptedCalls)
    }

    @Test fun encryptedCreationRequiresMatchingPasswordAndWipesCallbackArray() {
        var createdName: String? = null
        var seenPassword: String? = null
        var callbackArray: CharArray? = null
        compose.setContent {
            OpenCloudTheme {
                BrowserCreationDialog(
                    title = "New folder",
                    encryptLabel = "Encrypt folder",
                    onPlainCreate = {},
                    onEncryptedCreate = { name, password ->
                        createdName = name
                        seenPassword = String(password)
                        callbackArray = password
                    },
                    onDismiss = {},
                )
            }
        }
        compose.onNodeWithText("Name").performTextInput("Private")
        compose.onNodeWithText("Encrypt folder").assertExists()
        compose.onAllNodes(isToggleable())[0].performClick()
        compose.onNodeWithText("Vault password").performTextInput("correct horse battery")
        compose.onAllNodesWithContentDescription("Show password")[0].performClick()
        compose.onNodeWithContentDescription("Hide password").assertExists()
        compose.onNodeWithContentDescription("Hide password").performClick()
        compose.onNodeWithText("Confirm vault password").performTextInput("wrong password")
        compose.onNodeWithText("Create").assertIsNotEnabled()
        compose.onNodeWithText("Confirm vault password").performTextClearance()
        compose.onNodeWithText("Confirm vault password").performTextInput("correct horse battery")
        compose.onNodeWithText("Create").performClick()
        assertEquals("Private", createdName)
        assertEquals("correct horse battery", seenPassword)
        assertNotNull(callbackArray)
        assertTrue(callbackArray!!.all { it == '\u0000' })
    }

    @Test fun encryptedCreationRefusesShortPasswordAndAcceptsLongPassphrase() {
        var encryptedCalls = 0
        compose.setContent {
            OpenCloudTheme {
                BrowserCreationDialog(
                    title = "New Space",
                    encryptLabel = "Encrypt Space",
                    onPlainCreate = {},
                    onEncryptedCreate = { _, _ -> encryptedCalls++ },
                    onDismiss = {},
                )
            }
        }
        compose.onNodeWithText("Name").performTextInput("Archive")
        compose.onAllNodes(isToggleable())[0].performClick()
        compose.onNodeWithText("Vault password").performTextInput("short")
        compose.onNodeWithText("Confirm vault password").performTextInput("short")
        compose
            .onNodeWithText(
                "Use at least 12 characters, preferably several unrelated words. Choose a unique password.",
            ).assertExists()
        compose.onNodeWithText("Create").assertIsNotEnabled()
        assertEquals(0, encryptedCalls)

        compose.onNodeWithText("Vault password").performTextClearance()
        compose.onNodeWithText("Confirm vault password").performTextClearance()
        compose.onNodeWithText("Vault password").performTextInput("river maple orbit lantern")
        compose.onNodeWithText("Confirm vault password").performTextInput("river maple orbit lantern")
        compose.onNodeWithText("Create").performClick()
        assertEquals(1, encryptedCalls)
    }

    @Test fun busyCreationCannotSubmitAgain() {
        var calls = 0
        compose.setContent {
            OpenCloudTheme {
                BrowserCreationDialog(
                    title = "New Space",
                    encryptLabel = "Encrypt Space",
                    onPlainCreate = { calls++ },
                    onEncryptedCreate = null,
                    onDismiss = {},
                    busy = true,
                )
            }
        }
        compose.onNodeWithText("Name").performTextInput("Secure")
        compose.onNodeWithText("Create").assertIsNotEnabled()
        assertEquals(0, calls)
    }
}
