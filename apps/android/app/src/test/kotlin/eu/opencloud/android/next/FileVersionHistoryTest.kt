package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onLast
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.RemoteFileVersion
import eu.opencloud.android.next.feature.files.FileVersionHistoryDialog
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import java.util.Locale
import java.util.TimeZone

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "en-rUS-w360dp-h800dp")
class FileVersionHistoryTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    private val previousLocale = Locale.getDefault()
    private val previousTimeZone = TimeZone.getDefault()

    @Before fun fixedFormatting() {
        Locale.setDefault(Locale.US)
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"))
    }

    @After fun restoreFormatting() {
        Locale.setDefault(previousLocale)
        TimeZone.setDefault(previousTimeZone)
    }

    @Test fun folderShortcutIcon() {
        val context = org.robolectric.RuntimeEnvironment.getApplication()
        val drawable =
            requireNotNull(context.getDrawable(eu.opencloud.android.next.core.sync.R.mipmap.ic_folder_shortcut))
        val bitmap = android.graphics.Bitmap.createBitmap(216, 216, android.graphics.Bitmap.Config.ARGB_8888)
        drawable.setBounds(0, 0, 216, 216)
        drawable.draw(android.graphics.Canvas(bitmap))
        bitmap.captureRoboImage("src/test/snapshots/rendered/folder_shortcut_icon.png")
    }

    @Test fun restoreRequiresConfirmationAndShowsCompletion() {
        var calls = 0
        val resource =
            ResourceEntity(
                "a",
                "s",
                "r",
                null,
                "/notes.txt",
                "notes.txt",
                ResourceKind.FILE,
                "text/plain",
                20,
                "\"v2\"",
                0,
                0,
            )
        compose.setContent {
            OpenCloudTheme {
                FileVersionHistoryDialog(
                    resource,
                    {},
                    loadVersions = { listOf(RemoteFileVersion("v1", 1759406400000, 12)) },
                    restoreVersion = { _, _ -> calls++ },
                )
            }
        }
        compose.waitUntil(10_000) { compose.onAllNodesWithText("Restore").fetchSemanticsNodes().size == 1 }
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/version_history.png")
        compose.onNodeWithText("Restore").performClick()
        assertEquals(0, calls)
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(0, calls)
        compose.onNodeWithText("Restore").performClick()
        compose.onAllNodesWithText("Restore").onLast().performClick()
        compose.waitUntil(10_000) { calls == 1 }
        compose.waitUntil(10_000) {
            compose
                .onAllNodesWithText(
                    "Version restored. The file listing will refresh.",
                ).fetchSemanticsNodes()
                .isNotEmpty()
        }
    }
}
