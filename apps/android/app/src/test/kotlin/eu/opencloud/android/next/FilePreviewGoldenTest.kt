package eu.opencloud.android.next

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.Density
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.sync.TextDraft
import eu.opencloud.android.next.core.ui.FilePreviewScreen
import eu.opencloud.android.next.core.ui.FilePreviewState
import eu.opencloud.android.next.feature.files.TextEditorScreen
import eu.opencloud.android.next.feature.files.TextEditorState
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
class FilePreviewGoldenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun textPreviewSeparatesReadingFromEditing() {
        var edits = 0
        var external = 0
        compose.activity.setContent {
            OpenCloudTheme {
                FilePreviewScreen(
                    "Notes.txt",
                    FilePreviewState(
                        loading = false,
                        text = "Restored meeting notes\n\nThis is the current file on the server.",
                    ),
                    {
                    },
                    { external++ },
                    {},
                    {},
                    onEdit = { edits++ },
                )
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/text_preview.png")
        assertEquals(0, edits)
        compose.onNodeWithText("Open with").performClick()
        compose.onNodeWithText("Edit").performClick()
        assertEquals(1, edits)
        assertEquals(1, external)
    }

    @Test fun changedServerRequiresAnExplicitDraftChoice() = changedDraft(1f, "text_draft_changed")

    @Test
    @Config(qualifiers = "w412dp-h915dp")
    fun changedDraftRemainsReadableWithLargeFont() = changedDraft(1.3f, "text_draft_changed_large")

    private fun changedDraft(
        fontScale: Float,
        filename: String,
    ) {
        var current = 0
        var resumed = 0
        val draft =
            TextDraft(
                "account",
                "space",
                "notes",
                "/Notes.txt",
                "Notes.txt",
                "text/plain",
                "\"v1\"",
                "My unfinished changes",
            )
        compose.activity.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(LocalDensity provides Density(density.density, fontScale)) {
                OpenCloudTheme {
                    TextEditorScreen(TextEditorState(draft, busy = false, serverChanged = true, chooseDraft = true), {
                    }, {}, {}, { current++ }, onResumeDraft = { resumed++ })
                }
            }
        }
        compose.onNodeWithText("Save to server").assertIsNotEnabled()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/$filename.png")
        compose.onNodeWithText("View current file").performClick()
        compose.onNodeWithText("Resume draft").performClick()
        assertEquals(1, current)
        assertEquals(1, resumed)
    }

    @Test fun pdfPreviewProvidesPageNavigation() {
        var page = -1
        compose.activity.setContent {
            OpenCloudTheme {
                FilePreviewScreen(
                    "Scan.pdf",
                    FilePreviewState(
                        loading = false,
                        bitmap = documentImage(),
                        page = 0,
                        pages = 3,
                    ),
                    {
                    },
                    {},
                    {
                        page =
                            it
                    },
                    {},
                )
            }
        }
        compose.onNodeWithText("Previous").assertIsNotEnabled()
        compose.onNodeWithText("Next").performClick()
        assertEquals(1, page)
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/pdf_preview.png")
    }

    @Test fun imagePreviewShowsImageWithoutEditing() {
        compose.activity.setContent {
            OpenCloudTheme {
                FilePreviewScreen(
                    "Image.png",
                    FilePreviewState(loading = false, bitmap = documentImage()),
                    {},
                    {},
                    {},
                    {},
                )
            }
        }
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/image_preview.png")
    }

    private fun documentImage(): Bitmap =
        Bitmap.createBitmap(400, 600, Bitmap.Config.ARGB_8888).also {
            val canvas = Canvas(it)
            canvas.drawColor(Color.WHITE)
            val paint =
                Paint().apply {
                    color = Color.DKGRAY
                    textSize = 26f
                    isAntiAlias = true
                }
            canvas.drawText("Sample document", 32f, 64f, paint)
            paint.textSize = 18f
            canvas.drawText("Raiun file preview", 32f, 110f, paint)
        }
}
