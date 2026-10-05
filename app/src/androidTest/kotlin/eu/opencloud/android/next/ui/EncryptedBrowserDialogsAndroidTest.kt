package eu.opencloud.android.next.ui

import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextClearance
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream

@RunWith(AndroidJUnit4::class)
class EncryptedBrowserDialogsAndroidTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun visibleThumbnailCanOpenCopyMoveAndKeepOfflineActions() {
        val png = syntheticPng()
        val state = mutableStateOf(contents())
        val events = mutableListOf<String>()
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(
                        onLoadThumbnail = { id -> if (id == "photo") png.copyOf() else null },
                        onLoadDestinationFolders = { path ->
                            state.value =
                                state.value.copy(
                                    destinationPickerPath = path,
                                    destinationPickerEntries =
                                        if (path.isEmpty()) {
                                            listOf(
                                                folder("archive", "Archive", "Archive"),
                                            )
                                        } else {
                                            emptyList()
                                        },
                                )
                        },
                        onDismissDestinationPicker = {
                            state.value = state.value.copy(destinationPickerPath = null)
                            events += "dismiss"
                        },
                        onEntryAction = { id, action, destination ->
                            events += "$id:$action:$destination"
                            if (action == VaultEntryAction.KEEP_OFFLINE) state.value = state.value.copy(loading = true)
                        },
                    ),
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
        compose.onNodeWithContentDescription("Actions for photo.png").performClick()
        compose.onNodeWithText("Copy").performClick()
        compose.onNodeWithText("Archive").performClick()
        compose.onNodeWithText("Copy here").performClick()
        compose.onNodeWithContentDescription("Actions for photo.png").performClick()
        compose.onNodeWithText("Move").performClick()
        compose.onNodeWithText("Archive").performClick()
        compose.onNodeWithText("Move here").performClick()

        compose.onNodeWithContentDescription("Actions for photo.png").performClick()
        compose.onNodeWithText("Keep encrypted copy offline").performClick()
        compose.onNodeWithText("Confirm").performClick()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("vault-thumbnail-photo", useUnmergedTree = true).fetchSemanticsNodes().isEmpty()
        }
        compose.runOnIdle { state.value = state.value.copy(loading = false) }
        compose.waitUntil(5_000) {
            compose
                .onAllNodesWithTag(
                    "vault-thumbnail-photo",
                    useUnmergedTree = true,
                ).fetchSemanticsNodes()
                .isNotEmpty()
        }
        assertEquals(
            listOf(
                "photo:COPY:Archive",
                "dismiss",
                "photo:MOVE:Archive",
                "dismiss",
                "photo:KEEP_OFFLINE:null",
            ),
            events,
        )
        png.fill(0)
    }

    @Test
    fun thumbnailBrowserOpensImageAndPdfPreviews() {
        val png = syntheticPng()
        val pdf = singlePagePdf()
        val state = mutableStateOf(contents())
        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(
                        onLoadThumbnail = { id -> if (id == "photo") png.copyOf() else null },
                        onOpenPreview = { id ->
                            val isPdf = id == "document"
                            state.value =
                                state.value.copy(
                                    preview =
                                        VaultRoutePreview(
                                            title = if (isPdf) "document.pdf" else "photo.png",
                                            bytes = if (isPdf) pdf.copyOf() else png.copyOf(),
                                            kind = if (isPdf) VaultPreviewKind.PDF else VaultPreviewKind.IMAGE,
                                        ),
                                )
                        },
                        onDismissPreview = { state.value = state.value.copy(preview = null) },
                    ),
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
        compose.onNodeWithText("photo.png").performClick()
        compose.onNodeWithContentDescription("photo.png").assertExists()
        compose.onNodeWithContentDescription("Close").performClick()
        compose.onNodeWithText("document.pdf").performClick()
        compose.waitUntil(10_000) { compose.onAllNodesWithText("1 of 1").fetchSemanticsNodes().isNotEmpty() }
        compose.onNodeWithText("1 of 1").assertExists()
        compose.onNodeWithContentDescription("Close").performClick()
        png.fill(0)
        pdf.fill(0)
    }

    @Test
    fun encryptedTextEditorSavesUtf8ForTheSamePreviewAndWipesOwnedBytes() {
        val original = "initial encrypted text".encodeToByteArray()
        val preview = VaultRoutePreview("notes.txt", original.copyOf(), VaultPreviewKind.TEXT, editable = true)
        val state =
            mutableStateOf(
                contents().copy(
                    entries =
                        listOf(
                            VaultRouteEntry(
                                "notes",
                                "notes.txt",
                                "notes.txt",
                                false,
                                false,
                                original.size.toLong(),
                                "text/plain",
                            ),
                        ),
                ),
            )
        var savedPreview: VaultRoutePreview? = null
        var savedText: String? = null
        var savedBytesWiped = false

        compose.setContent {
            OpenCloudTheme {
                VaultScreen(
                    state.value,
                    callbacks().copy(
                        onOpenPreview = { state.value = state.value.copy(preview = preview) },
                        onSavePreviewText = { receivedPreview, bytes ->
                            savedPreview = receivedPreview
                            savedText = bytes.toString(Charsets.UTF_8)
                            bytes.fill(0)
                            savedBytesWiped = bytes.all { it == 0.toByte() }
                        },
                    ),
                )
            }
        }

        compose.onNodeWithText("notes.txt").performClick()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithText("initial encrypted text").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithText("initial encrypted text").assertExists()
        compose.onNodeWithText("Edit").performClick()
        compose.onNodeWithText("UTF-8 text").assertExists()
        compose.onNodeWithText("initial encrypted text").performTextClearance()
        compose.onNodeWithText("UTF-8 text").performTextInput("updated Grüße")
        compose.onNodeWithText("Save to server").performClick()

        compose.runOnIdle {
            assertSame(preview, savedPreview)
            assertEquals("updated Grüße", savedText)
            assertEquals(true, savedBytesWiped)
        }
        original.fill(0)
        preview.bytes.fill(0)
    }

    private fun contents() =
        VaultRouteState(
            mode = VaultRouteMode.CONTENTS,
            selectedTitle = "Private files",
            selectedLocation = VaultRouteLocation("synthetic", "Private files", VaultLocationKindUi.FOLDER_VAULT, true),
            entries = listOf(image("photo", "photo.png"), image("document", "document.pdf")),
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

    private fun image(
        id: String,
        name: String,
    ) = VaultRouteEntry(id, name, name, false, false, 1, if (id == "document") "application/pdf" else "image/png")

    private fun folder(
        id: String,
        name: String,
        path: String,
    ) = VaultRouteEntry(id, name, path, true, false, 0, null)

    private fun syntheticPng(): ByteArray {
        val bitmap = Bitmap.createBitmap(24, 24, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.BLUE) }
        return ByteArrayOutputStream()
            .also { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
            .toByteArray()
            .also { bitmap.recycle() }
    }

    private fun singlePagePdf(): ByteArray {
        val content = StringBuilder("%PDF-1.4\n")
        val offsets = mutableListOf<Int>()
        listOf(
            "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
            "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
            "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 240 360] /Resources << >> /Contents 4 0 R >>\nendobj\n",
            "4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
        ).forEach { objectText ->
            offsets += content.toString().encodeToByteArray().size
            content.append(objectText)
        }
        val xrefOffset = content.toString().encodeToByteArray().size
        content.append("xref\n0 5\n0000000000 65535 f \n")
        offsets.forEach { offset -> content.append(offset.toString().padStart(10, '0')).append(" 00000 n \n") }
        content
            .append("trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n")
            .append(xrefOffset)
            .append("\n%%EOF\n")
        return content.toString().encodeToByteArray()
    }
}
