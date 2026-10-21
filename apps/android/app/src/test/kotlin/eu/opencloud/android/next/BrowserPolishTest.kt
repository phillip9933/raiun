package eu.opencloud.android.next

import android.graphics.Bitmap
import android.graphics.Color
import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTouchInput
import androidx.compose.ui.unit.IntSize
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.sync.FolderIconColor
import eu.opencloud.android.next.core.sync.FolderShortcutIcon
import eu.opencloud.android.next.core.sync.SharedDownloadFile
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import eu.opencloud.android.next.core.ui.FolderIconCrop
import eu.opencloud.android.next.feature.files.FolderShortcutPicker
import eu.opencloud.android.next.feature.settings.SettingsScreen
import eu.opencloud.android.next.feature.shares.IncomingBrowserItem
import eu.opencloud.android.next.feature.shares.IncomingBrowserScreen
import eu.opencloud.android.next.feature.shares.IncomingBrowserState
import eu.opencloud.android.next.feature.shares.IncomingFileAction
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class BrowserPolishTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)
    @Test
    fun sharedCloudFileOpensFromEveryLayoutWithoutCopyAction() {
        val layout = mutableStateOf(SettingsBrowserLayout.DEFAULT_TABLE)
        val folder =
            IncomingBrowserItem.Folder(
                "Raiun Testing",
                SharedFolderRequest("account", "share", "scope", "root", "/"),
            )
        val file =
            IncomingBrowserItem.File(
                "Raiun.apk",
                SharedDownloadRequest(
                    "account",
                    "share",
                    "scope",
                    SharedDownloadFile("apk", "/Raiun.apk", 108000000, "v1"),
                ),
                "application/vnd.android.package-archive",
            )
        var opens = 0
        var copies = 0
        var action: IncomingFileAction? = null
        compose.setContent {
            // Capture settled layout without platform ripple timing affecting the golden.
            androidx.compose.runtime.CompositionLocalProvider(
                androidx.compose.material3.LocalRippleConfiguration provides null,
            ) {
                OpenCloudTheme {
                    IncomingBrowserScreen(
                        IncomingBrowserState(account = "account", trail = listOf(folder), items = listOf(file)),
                        {},
                        {},
                        {
                            assertEquals(file, it)
                            opens++
                        },
                        null,
                        { _, _ -> copies++ },
                        {},
                        layout = layout.value,
                        onLayout = { layout.value = it },
                        onFileAction = { _, chosen ->
                            action =
                                chosen
                        },
                    )
                }
            }
        }
        compose.onNodeWithText("Raiun.apk").performClick()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/shared_browser_list.png")
        compose.onNodeWithContentDescription("Switch to compact list view").performClick()
        compose.onNodeWithText("Raiun.apk").performClick()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/shared_browser_compact.png")
        compose.onNodeWithContentDescription("Switch to grid view").performClick()
        compose.onNodeWithText("Raiun.apk").performClick()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/shared_browser_tiles.png")
        assertEquals(3, opens)
        assertEquals(0, copies)
        compose.onNodeWithContentDescription("Actions for Raiun.apk").performClick()
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/shared_browser_actions.png")
        compose.onNodeWithText("Open with").performClick()
        assertEquals(IncomingFileAction.OPEN_WITH, action)
        compose.onNodeWithContentDescription("Switch to regular list view").performClick()
        assertEquals(SettingsBrowserLayout.DEFAULT_TABLE, layout.value)
    }

    @Test fun openingSettingsAreInTheirOwnScreen() {
        compose.setContent { OpenCloudTheme { SettingsScreen(UserSettings(), {}, {}, {}) } }
        compose.onAllNodesWithText("PDF documents").assertCountEquals(0)
        compose.onNodeWithText("Opening files").performClick()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/settings_opening_files.png")
        compose.onNodeWithContentDescription("Back").performClick()
        compose.onAllNodesWithText("PDF documents").assertCountEquals(0)
        compose.onNodeWithText("Appearance").performClick()
    }

    @Test fun shortcutOffersColorsAndImagePickerBeforePinning() {
        val color = mutableStateOf(FolderIconColor.DEFAULT)
        var images = 0
        var pins = 0
        compose.setContent {
            OpenCloudTheme {
                FolderShortcutPicker(color.value, null, false, { color.value = it }, { images++ }, { pins++ }, {})
            }
        }
        compose.onNodeWithText("Blue").performClick()
        compose.onNodeWithText("Blue").assertIsSelected()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/folder_shortcut_picker.png")
        compose.onNodeWithText("Choose image").performClick()
        assertEquals(1, images)
        assertEquals(0, pins)
        compose.onNodeWithText("Add to home screen").performClick()
        assertEquals(1, pins)
    }

    @Test fun allShareTabsOfferTheSameLayoutAndRefreshControls() {
        val category = mutableStateOf(eu.opencloud.android.next.feature.shares.ShareCategory.BY_ME)
        val layout = mutableStateOf(SettingsBrowserLayout.DEFAULT_TABLE)
        var refreshed = 0
        compose.setContent {
            OpenCloudTheme {
                eu.opencloud.android.next.feature.shares.SharesContent(
                    eu.opencloud.android.next.feature.shares
                        .SharesUiState(category = category.value),
                    { category.value = it },
                    { refreshed++ },
                    { _, _ -> },
                    {},
                    {},
                    layout = layout.value,
                    onLayout = { layout.value = it },
                )
            }
        }
        compose.onNodeWithContentDescription("Refresh shared folder").performClick()
        compose.onNodeWithContentDescription("Switch to compact list view").performClick()
        assertEquals(SettingsBrowserLayout.CONDENSED_TABLE, layout.value)
        compose.onNodeWithText("Public links").performClick()
        compose.onNodeWithContentDescription("Refresh shared folder").performClick()
        compose.onNodeWithContentDescription("Switch to grid view").performClick()
        assertEquals(SettingsBrowserLayout.TILES, layout.value)
        compose.onNodeWithText("Shared with me").performClick()
        compose.onNodeWithContentDescription("Refresh shared folder").performClick()
        assertEquals(3, refreshed)
    }

    @Test fun cancellingFolderEnumerationKeepsAlreadyAcceptedQueueCount() {
        val accepted =
            java.util.concurrent.atomic
                .AtomicInteger()
        val stopped =
            java.util.concurrent.atomic
                .AtomicBoolean()
        var closed = false
        compose.setContent {
            OpenCloudTheme {
                eu.opencloud.android.next.core.ui.FolderDownloadDialog("Shared folder", { closed = true }) { progress ->
                    try {
                        accepted.incrementAndGet()
                        progress(accepted.get())
                        kotlinx.coroutines.awaitCancellation()
                    } finally {
                        stopped.set(true)
                    }
                }
            }
        }
        compose.onNodeWithText("Download folder").performClick()
        compose.waitUntil(5000) { accepted.get() == 1 }
        compose.onNodeWithText("1 files added to Transfers").assertExists()
        compose.onNodeWithText("Cancel").performClick()
        compose.waitUntil(5000) { stopped.get() }
        assertEquals(1, accepted.get())
        assertEquals(true, closed)
    }

    @Test fun cropSelectsSquareRegionAndOnlyAppliesOnConfirmation() {
        val source = Bitmap.createBitmap(80, 40, Bitmap.Config.ARGB_8888)
        for (x in 0 until 80) for (y in 0 until 40) source.setPixel(x, y, if (x < 40) Color.RED else Color.BLUE)
        val left =
            eu.opencloud.android.next.core.ui
                .cropFolderIcon(source, 1f, 0f, 0f)
        val right =
            eu.opencloud.android.next.core.ui
                .cropFolderIcon(source, 2f, 1f, 1f)
        assertEquals(40, left.width)
        assertEquals(40, left.height)
        assertEquals(Color.RED, left.getPixel(39, 39))
        assertEquals(20, right.width)
        assertEquals(Color.BLUE, right.getPixel(0, 0))
        var applied: Bitmap? = null
        compose.setContent {
            OpenCloudTheme {
                eu.opencloud.android.next.core.ui
                    .FolderIconCropDialog(source, {}, { applied = it })
            }
        }
        assertEquals(null, applied)
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/folder_icon_crop.png")
        compose.onNodeWithText("Use image").performClick()
        assertEquals(40, applied?.width)
        assertEquals(40, applied?.height)
        assertEquals(80, source.width)
    }

    @Test fun customIconUsesAdaptiveFormatAndFillsTheLauncherMask() {
        val default = FolderShortcutIcon.render(compose.activity)
        val blue = FolderShortcutIcon.render(compose.activity, FolderIconColor.BLUE)
        assertNotEquals(default.getPixel(108, 108), blue.getPixel(108, 108))
        val source = Bitmap.createBitmap(80, 40, Bitmap.Config.ARGB_8888)
        for (x in 0 until 80) for (y in 0 until 40) source.setPixel(x, y, if (x < 40) Color.RED else Color.BLUE)
        val layer = FolderShortcutIcon.render(compose.activity, image = source)
        val icon = FolderShortcutIcon.launcherIcon(compose.activity, layer)
        assertEquals(android.graphics.drawable.Icon.TYPE_ADAPTIVE_BITMAP, icon.type)
        val preview = FolderShortcutIcon.preview(compose.activity, FolderIconColor.DEFAULT, source)
        val drawable = requireNotNull(icon.loadDrawable(compose.activity))
        org.junit.Assert.assertTrue(drawable is android.graphics.drawable.AdaptiveIconDrawable)
        val actual = Bitmap.createBitmap(preview.width, preview.height, Bitmap.Config.ARGB_8888)
        drawable.setBounds(0, 0, actual.width, actual.height)
        drawable.draw(android.graphics.Canvas(actual))
        listOf(10 to 72, 134 to 72, 60 to 10, 85 to 134).forEach { (x, y) ->
            assertEquals(preview.getPixel(x, y), actual.getPixel(x, y))
            assertEquals(255, Color.alpha(actual.getPixel(x, y)))
        }
        assertEquals(Color.RED, actual.getPixel(10, 72))
        assertEquals(Color.BLUE, actual.getPixel(134, 72))
        compose.setContent {
            OpenCloudTheme { FolderShortcutPicker(FolderIconColor.DEFAULT, source, false, {}, {}, {}, {}) }
        }
        compose.onNode(isDialog()).captureRoboImage("src/test/snapshots/rendered/folder_custom_icon.png")
    }

    @Test fun cropGesturesKeepTheFingerAnchorAndClampImageEdges() {
        val source = IntSize(400, 200)
        val zoomed = FolderIconCrop().transformed(source, 200f, Offset(50f, 100f), Offset.Zero, 2f)
        assertEquals(2f, zoomed.zoom)
        assertEquals(125f, (400f - 100f) * zoomed.horizontal, 0.01f)
        val moved = zoomed.transformed(source, 200f, Offset(50f, 100f), Offset(100f, 0f), 1f)
        assertEquals(75f, (400f - 100f) * moved.horizontal, 0.01f)
        val edge = moved.transformed(source, 200f, Offset.Zero, Offset(10000f, -10000f), 100f)
        assertEquals(4f, edge.zoom)
        assertEquals(0f, edge.horizontal)
        assertEquals(1f, edge.vertical)
        val reset = edge.transformed(source, 200f, Offset.Zero, Offset.Zero, 0.01f)
        assertEquals(1f, reset.zoom)
        assertEquals(0.5f, reset.vertical)
    }

    @Test fun imageCropRespondsToPinchAndDragWithoutSliders() {
        val source = Bitmap.createBitmap(80, 40, Bitmap.Config.ARGB_8888).apply { eraseColor(Color.RED) }
        var applied: Bitmap? = null
        compose.setContent {
            OpenCloudTheme {
                eu.opencloud.android.next.core.ui
                    .FolderIconCropDialog(source, {}, { applied = it })
            }
        }
        compose.onAllNodesWithText("Horizontal position").assertCountEquals(0)
        compose.onNodeWithContentDescription("Shortcut icon preview").performTouchInput {
            down(0, Offset(width * 0.4f, centerY))
            down(1, Offset(width * 0.6f, centerY))
            for (step in 1..6) {
                moveTo(0, Offset(width * (0.4f - step * 0.025f), centerY))
                moveTo(1, Offset(width * (0.6f + step * 0.025f), centerY))
            }
            up(0)
            up(1)
        }
        compose.onNodeWithContentDescription("Shortcut icon preview").performTouchInput {
            down(center)
            moveTo(Offset(width * 0.75f, centerY))
            up()
        }
        compose.onNodeWithText("Use image").performClick()
        org.junit.Assert.assertTrue(requireNotNull(applied).width < 40)
        assertEquals(applied?.width, applied?.height)
    }
}
