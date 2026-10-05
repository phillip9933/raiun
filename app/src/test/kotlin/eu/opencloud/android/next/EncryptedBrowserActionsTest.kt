package eu.opencloud.android.next

import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.VaultEntryAction
import eu.opencloud.android.next.ui.VaultLocationKindUi
import eu.opencloud.android.next.ui.VaultRouteCallbacks
import eu.opencloud.android.next.ui.VaultRouteEntry
import eu.opencloud.android.next.ui.VaultRouteLocation
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
import java.io.ByteArrayOutputStream

@GraphicsMode(GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class EncryptedBrowserActionsTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun encryptedImagesShowMemoryOnlyBrowserThumbnails() {
        val bitmap = Bitmap.createBitmap(64, 64, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.BLUE) }
        val png = ByteArrayOutputStream().also { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }.toByteArray()
        bitmap.recycle()
        val photo = VaultRouteEntry("photo", "photo.jpg", "photo.jpg", false, false, png.size.toLong(), "image/jpeg")
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    contents().copy(entries = listOf(photo)),
                    callbacks().copy(onLoadThumbnail = { png.copyOf() }),
                )
            }
        }
        compose.waitUntil(5_000) {
            compose
                .onAllNodesWithTag(
                    "vault-thumbnail-photo",
                    useUnmergedTree = true,
                ).fetchSemanticsNodes()
                .isNotEmpty()
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_image_thumbnail.png")
        png.fill(0)
    }

    @Test fun encryptedContentsOfferNormalRefreshAndFolderActions() {
        var refreshes = 0
        compose.setContent {
            OpenCloudTheme { VaultScreen(contents(), callbacks().copy(onRetry = { refreshes++ })) }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_browser.png")
        compose.onAllNodesWithText("Encrypted folder").assertCountEquals(1)
        compose.onNodeWithContentDescription("Refresh").performClick()
        assertEquals(1, refreshes)
        compose.onNodeWithContentDescription("Actions for Documents").performClick()
        compose.onAllNodesWithText("Rename").assertCountEquals(1)
        compose.onAllNodesWithText("Delete").assertCountEquals(1)
        compose.onAllNodesWithText("Move").assertCountEquals(1)
        compose.onAllNodesWithText("Save a decrypted copy").assertCountEquals(0)
    }

    @Test fun offlineBrowserHasNoMutationActionsAndLabelsSnapshotClearly() {
        var openedWith = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    contents().copy(offline = true),
                    callbacks().copy(onEntryAction = { _, action, _ ->
                        if (action ==
                            VaultEntryAction.OPEN_WITH
                        ) {
                            openedWith++
                        }
                    }),
                )
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_browser_offline.png")
        compose.onAllNodesWithText("Encrypted offline copy · read only").assertCountEquals(1)
        compose.onAllNodesWithContentDescription("New actions").assertCountEquals(0)
        compose.onNodeWithContentDescription("Actions for notes.txt").performClick()
        compose.onAllNodesWithText("Rename").assertCountEquals(0)
        compose.onAllNodesWithText("Delete").assertCountEquals(0)
        compose.onAllNodesWithText("Save a decrypted copy").assertCountEquals(1)
        compose.onAllNodesWithText("Open with").assertCountEquals(1)
        compose.onAllNodesWithText("Keep encrypted copy offline").assertCountEquals(0)
        compose.onNodeWithText("Open with").performClick()
        assertEquals(1, openedWith)
    }

    @Test fun encryptedRowsShowTypeSizeAndHonestAvailabilityStatus() {
        val state = mutableStateOf(contents())
        compose.setContent { OpenCloudTheme { VaultScreen(state.value, callbacks()) } }
        compose.onAllNodesWithContentDescription("Encrypted item; offline availability unknown").assertCountEquals(2)
        compose.onAllNodesWithText("12 B").assertCountEquals(1)
        compose.onAllNodesWithText("Folder").assertCountEquals(1)

        compose.runOnIdle { state.value = contents().copy(offline = true) }
        compose.onAllNodesWithContentDescription("Available in encrypted offline copy").assertCountEquals(2)
        compose.runOnIdle {
            state.value =
                contents().copy(entries = contents().entries.map { it.copy(offlineAvailable = false) })
        }
        compose.onAllNodesWithContentDescription("Cloud only").assertCountEquals(2)
        compose.runOnIdle {
            state.value =
                contents().copy(entries = contents().entries.map { it.copy(offlineAvailable = true) })
        }
        compose.onAllNodesWithContentDescription("Available in encrypted offline copy").assertCountEquals(2)
    }

    @Test fun offlinePinRequiresConfirmation() {
        var pins = 0
        compose.setContent {
            OpenCloudTheme { VaultScreen(contents(), callbacks().copy(onKeepDirectoryOffline = { pins++ })) }
        }
        compose.onNodeWithContentDescription("Actions for Private files").performClick()
        compose.onNodeWithText("Keep encrypted copy offline").performClick()
        assertEquals(0, pins)
        compose.onNodeWithText("Confirm").performClick()
        assertEquals(1, pins)
    }

    @Test fun createAndUploadActionsLiveUnderOneFloatingAddButton() {
        var uploads = 0
        var createdFolder: String? = null
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    contents(),
                    callbacks().copy(onUpload = { uploads++ }, onCreateFolder = { createdFolder = it }),
                )
            }
        }

        compose.onNodeWithContentDescription("New actions").performClick()
        compose.onNodeWithContentDescription("New folder").assertHasClickAction()
        compose.onNodeWithContentDescription("Upload file").assertHasClickAction()
        compose.onAllNodesWithContentDescription("Edit encrypted location").assertCountEquals(1)
        compose.onNodeWithContentDescription("Upload file").performClick()
        assertEquals(1, uploads)
        assertEquals(null, createdFolder)
    }

    @Test fun exportingNeedsExplicitDecryptionWarningAndCancelDoesNotExport() {
        var exports = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    contents(),
                    callbacks().copy(onEntryAction = { _, action, _ ->
                        if (action == VaultEntryAction.SAVE_COPY) exports++
                    }),
                )
            }
        }
        compose.onNodeWithContentDescription("Actions for notes.txt").performClick()
        compose.onNodeWithText("Save a decrypted copy").performClick()
        compose
            .onAllNodesWithText(
                "The saved copy will no longer be encrypted by this folder or Space. Only save it to a location you trust.",
            ).assertCountEquals(1)
        assertEquals(0, exports)
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(0, exports)
    }

    @Test fun copyAndMoveChooseOnlyFoldersInsideTheCurrentEncryptedLocation() {
        val state =
            mutableStateOf(
                contents().copy(
                    destinationPickerPath = "",
                    destinationPickerEntries =
                        listOf(
                            VaultRouteEntry("self", "Documents", "Documents", true, false, 0, null),
                            VaultRouteEntry("child", "Nested", "Documents/Nested", true, false, 0, null),
                            VaultRouteEntry("sibling", "Other", "Other", true, false, 0, null),
                            VaultRouteEntry("guide", "Guide.txt", "Guide.txt", false, false, 4, "text/plain"),
                        ),
                ),
            )
        val rootEntries = state.value.destinationPickerEntries
        val events = mutableListOf<String>()
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(
                        onLoadDestinationFolders = { path ->
                            events += "load:$path"
                            state.value =
                                state.value.copy(
                                    destinationPickerPath = path,
                                    destinationPickerEntries =
                                        if (path == "Other") {
                                            listOf(VaultRouteEntry("deep", "Deep", "Other/Deep", true, false, 0, null))
                                        } else {
                                            rootEntries
                                        },
                                )
                        },
                        onDismissDestinationPicker = {
                            events += "dismiss"
                            state.value =
                                state.value.copy(destinationPickerPath = null, destinationPickerEntries = emptyList())
                        },
                        onOpenVaultFolder = { events += "open:$it" },
                        onEntryAction = { id, action, path -> events += "action:$id:$action:$path" },
                    ),
                )
            }
        }

        compose.onNodeWithContentDescription("Actions for Documents").performClick()
        compose.onNodeWithText("Move").performClick()
        compose.onAllNodesWithText("Documents").assertCountEquals(0)
        compose.onAllNodesWithText("Nested").assertCountEquals(0)
        compose.onNodeWithText("Guide.txt").assertExists()
        compose.onNodeWithText("Guide.txt").performClick()
        assertEquals(listOf("load:"), events)
        compose.onNodeWithText("Other").performClick()
        compose.onAllNodesWithText("Private files / Other").assertCountEquals(1)
        compose.onNodeWithText("Move here").assertExists()
        compose.onNodeWithText("Cancel").assertExists()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/encrypted_destination_picker.png")
        compose.onNodeWithContentDescription("Navigate up").performClick()
        assertEquals(listOf("load:", "load:Other", "load:"), events)
        compose.onNodeWithText("Other").performClick()
        compose.onNodeWithText("Move here").performClick()

        assertEquals(
            listOf("load:", "load:Other", "load:", "load:Other", "action:folder:MOVE:Other", "dismiss"),
            events,
        )
    }

    @Test fun copyUsesTheSameInVaultFolderPicker() {
        val state =
            mutableStateOf(
                contents().copy(
                    destinationPickerPath = "",
                    destinationPickerEntries =
                        listOf(VaultRouteEntry("sibling", "Other", "Other", true, false, 0, null)),
                ),
            )
        val events = mutableListOf<String>()
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(
                        onLoadDestinationFolders = { path ->
                            events += "load:$path"
                            state.value = state.value.copy(destinationPickerPath = path)
                        },
                        onDismissDestinationPicker = {
                            events += "dismiss"
                            state.value = state.value.copy(destinationPickerPath = null)
                        },
                        onEntryAction = { id, action, path -> events += "action:$id:$action:$path" },
                    ),
                )
            }
        }

        compose.onNodeWithContentDescription("Actions for notes.txt").performClick()
        compose.onNodeWithText("Copy").performClick()
        compose.onNodeWithText("Other").performClick()
        compose.onNodeWithText("Copy here").performClick()

        assertEquals(listOf("load:", "load:Other", "action:file:COPY:Other", "dismiss"), events)
    }

    @Test fun lockClearsPendingDestructiveConfirmation() {
        val state = mutableStateOf(contents())
        var deletes = 0
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(onEntryAction = { _, action, _ ->
                        if (action == VaultEntryAction.DELETE) deletes++
                    }),
                )
            }
        }
        compose.onNodeWithContentDescription("Actions for notes.txt").performClick()
        compose.onNodeWithText("Delete").performClick()
        compose.runOnIdle {
            state.value =
                state.value.copy(mode = VaultRouteMode.UNLOCK, entries = emptyList(), lockRevision = 1)
        }
        compose.onAllNodesWithText("Delete").assertCountEquals(0)
        assertEquals(0, deletes)
    }

    private fun contents() =
        VaultRouteState(
            mode = VaultRouteMode.CONTENTS,
            selectedTitle = "Private files",
            selectedLocation = VaultRouteLocation("synthetic", "Private files", VaultLocationKindUi.FOLDER_VAULT, true),
            entries =
                listOf(
                    VaultRouteEntry("folder", "Documents", "Documents", true, false, 0, null),
                    VaultRouteEntry("file", "notes.txt", "notes.txt", false, false, 12, "text/plain"),
                ),
        )

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
