package eu.opencloud.android.next.ui

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.concurrent.atomic.AtomicInteger

class EncryptedThumbnailOwnershipAndroidTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun thumbnailOwnerChangesDoNotReuseRecycledBitmapAndActionsRemainAvailable() {
        val png = syntheticPng()
        val opened = AtomicInteger()
        compose.setContent {
            var entry by remember { mutableStateOf(imageEntry("photo-a")) }
            var revision by remember { mutableLongStateOf(0L) }
            var enabled by remember { mutableStateOf(true) }
            Column {
                EncryptedThumbnail(
                    entry = entry,
                    revision = revision,
                    enabled = enabled,
                    modifier = Modifier.size(96.dp),
                    load = { png.copyOf() },
                )
                Button(
                    modifier = Modifier.testTag("change-thumbnail-owner"),
                    onClick = {
                        entry = imageEntry("photo-b")
                        revision++
                    },
                ) { Text("Change entry") }
                Button(
                    modifier = Modifier.testTag("change-thumbnail-revision"),
                    onClick = { revision++ },
                ) { Text("Refresh") }
                Button(
                    modifier = Modifier.testTag("toggle-thumbnail-loading"),
                    onClick = { enabled = !enabled },
                ) { Text("Toggle loading") }
                Button(
                    modifier = Modifier.testTag("open-encrypted-entry"),
                    onClick = { opened.incrementAndGet() },
                ) { Text("Open") }
            }
        }

        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("vault-thumbnail-photo-a").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("change-thumbnail-revision").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("vault-thumbnail-photo-a").assertExists()
        compose.onNodeWithTag("change-thumbnail-owner").performClick()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("vault-thumbnail-photo-b").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("vault-thumbnail-photo-a").assertDoesNotExist()
        compose.onNodeWithTag("vault-thumbnail-photo-b").assertExists()
        compose.onNodeWithTag("toggle-thumbnail-loading").performClick()
        compose.waitForIdle()
        compose.onNodeWithTag("vault-thumbnail-photo-b").assertDoesNotExist()
        compose.onNodeWithTag("toggle-thumbnail-loading").performClick()
        compose.waitUntil(5_000) {
            compose.onAllNodesWithTag("vault-thumbnail-photo-b").fetchSemanticsNodes().isNotEmpty()
        }
        compose.onNodeWithTag("open-encrypted-entry").performClick()
        assertEquals(1, opened.get())
        png.fill(0)
    }

    private fun imageEntry(id: String) =
        VaultRouteEntry(
            id = id,
            name = "$id.png",
            path = id,
            isFolder = false,
            isVaultRoot = false,
            size = 1,
            contentType = "image/png",
        )

    private fun syntheticPng(): ByteArray {
        val bitmap = Bitmap.createBitmap(8, 8, Bitmap.Config.ARGB_8888)
        val output = ByteArrayOutputStream()
        try {
            check(bitmap.compress(Bitmap.CompressFormat.PNG, 100, output))
            return output.toByteArray()
        } finally {
            bitmap.recycle()
        }
    }
}
