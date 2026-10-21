package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasSetTextAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.VaultPreviewKind
import eu.opencloud.android.next.ui.VaultRouteCallbacks
import eu.opencloud.android.next.ui.VaultRouteMode
import eu.opencloud.android.next.ui.VaultRoutePreview
import eu.opencloud.android.next.ui.VaultRouteState
import eu.opencloud.android.next.ui.VaultScreen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class EncryptedTextPreviewTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun editableTextIsChangedInSecurePreviewAndPassedOnlyToSaveCallback() {
        val preview =
            VaultRoutePreview("notes.txt", "Original text".toByteArray(), VaultPreviewKind.TEXT, editable = true)
        val state = mutableStateOf(VaultRouteState(mode = VaultRouteMode.CONTENTS, preview = preview))
        var savedText: String? = null
        var receivedPreview: VaultRoutePreview? = null
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(
                        onSavePreviewText = { target, bytes ->
                            receivedPreview = target
                            savedText = bytes.toString(Charsets.UTF_8)
                            bytes.fill(0)
                        },
                    ),
                )
            }
        }

        compose.onNodeWithText("Edit").assertExists()
        compose.waitForIdle()
        compose.mainClock.advanceTimeByFrame()
        compose.waitForIdle()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_text_preview.png")
        compose.onNodeWithText("Edit").performClick()
        compose.onNodeWithText("Discard draft").assertExists()
        compose.onNodeWithText("Cancel").assertDoesNotExist()
        compose.onNode(hasSetTextAction()).performTextClearance()
        compose.onNode(hasSetTextAction()).performTextInput("Updated text")
        compose.waitForIdle()
        compose.mainClock.advanceTimeByFrame()
        compose.waitForIdle()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_text_editor.png")
        compose.onNodeWithText("Save to server").performClick()
        compose.runOnIdle {
            assertSame(preview, receivedPreview)
            assertEquals("Updated text", savedText)
        }
    }

    @Test fun offlinePreviewRemainsReadOnlyAndDiscardClearsUnsavedEditor() {
        val preview = VaultRoutePreview("notes.txt", "Original text".toByteArray(), VaultPreviewKind.TEXT)
        val state = mutableStateOf(VaultRouteState(mode = VaultRouteMode.CONTENTS, preview = preview))
        var dismissed = false
        compose.setContent {
            OpenCloudTheme { VaultScreen(state.value, callbacks().copy(onDismissPreview = { dismissed = true })) }
        }

        compose.onNodeWithText("Edit").assertDoesNotExist()
        compose.runOnIdle { state.value = state.value.copy(preview = preview.copy(editable = true)) }
        compose.onNodeWithText("Edit").performClick()
        compose.onNode(hasSetTextAction()).performTextClearance()
        compose.onNode(hasSetTextAction()).performTextInput("Unsaved change")
        compose.onNodeWithContentDescription("Close").performClick()
        compose.onNodeWithText("Discard unsaved changes?").assertExists()
        compose.onNodeWithText("Discard changes").performClick()
        compose.runOnIdle { assertEquals(true, dismissed) }
    }

    @Test fun failedSaveRetainsDraftDisablesResaveAndRequiresDiscardConfirmation() {
        val preview =
            VaultRoutePreview("notes.txt", "Original text".toByteArray(), VaultPreviewKind.TEXT, editable = true)
        val state = mutableStateOf(VaultRouteState(mode = VaultRouteMode.CONTENTS, preview = preview))
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(
                        onSavePreviewText = { target, bytes ->
                            assertSame(preview, target)
                            bytes.fill(0)
                            state.value = state.value.copy(previewSaving = true)
                        },
                        onDismissPreview = { state.value = state.value.copy(preview = null) },
                    ),
                )
            }
        }

        compose.onNodeWithText("Edit").performClick()
        compose.onNode(hasSetTextAction()).performTextClearance()
        compose.onNode(hasSetTextAction()).performTextInput("Updated text")
        compose.onNodeWithText("Save to server").performClick()
        compose.onNodeWithContentDescription("Close").performClick()
        compose.onNodeWithText("Discard unsaved changes?").assertDoesNotExist()

        compose.runOnIdle {
            state.value =
                state.value.copy(
                    preview = preview.copy(editable = false),
                    previewSaving = false,
                    previewSaveError = eu.opencloud.android.next.ui.VaultRouteError.OPERATION,
                )
        }
        compose.onNodeWithText("Save to server").assertIsNotEnabled()
        compose.runOnIdle {
            val text = compose.onNode(hasSetTextAction()).fetchSemanticsNode().config[SemanticsProperties.EditableText]
            assertEquals("Updated text", text.text)
        }

        compose.onNodeWithContentDescription("Close").performClick()
        compose.onNodeWithText("Discard unsaved changes?").assertExists()
        val cancelButtons = compose.onAllNodesWithText("Cancel")
        cancelButtons.assertCountEquals(1)
        cancelButtons[0].performClick()
        compose.onNodeWithText("Discard unsaved changes?").assertDoesNotExist()
        compose.runOnIdle {
            val text = compose.onNode(hasSetTextAction()).fetchSemanticsNode().config[SemanticsProperties.EditableText]
            assertEquals("Updated text", text.text)
        }
        compose.onNodeWithText("Discard draft").performClick()
        compose.onNodeWithText("Discard unsaved changes?").assertExists()
        compose.onNodeWithText("Discard changes").performClick()
        compose.onNodeWithText("Original text").assertExists()
        compose.onNodeWithText("Edit").assertDoesNotExist()
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
