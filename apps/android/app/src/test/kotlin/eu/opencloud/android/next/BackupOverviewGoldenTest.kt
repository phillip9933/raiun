package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performScrollToIndex
import com.github.takahirom.roborazzi.RoborazziOptions
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class BackupOverviewGoldenTest {
    @get:Rule val composeRule = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun fileBrowserBackupSettings_matchesGolden() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                eu.opencloud.android.next.feature.files.BackupOverview(
                    backups =
                        listOf(
                            FolderBackupEntity(
                                id = "camera-backup",
                                accountId = "account",
                                spaceId = "personal",
                                sourceTreeUri = "content://provider/tree/primary%3ADCIM",
                                sourceDisplayName = "DCIM",
                                destinationPath = "/Camera Uploads",
                                mediaType = "IMAGE",
                                wifiOnly = true,
                                chargingOnly = true,
                                deleteAfterUpload = false,
                            ),
                        ),
                    onManage = {},
                )
            }
        }
        composeRule.onNodeWithText("DCIM").fetchSemanticsNode()
        composeRule.onRoot().captureRoboImage(
            filePath = "src/test/snapshots/rendered/file_browser_backup_settings.png",
            roborazziOptions = browserRoborazziOptions(),
        )
    }

    @Test
    fun fileBrowserBackupSettings_scrollsToLastActivePair() {
        composeRule.activity.setContent {
            OpenCloudTheme {
                eu.opencloud.android.next.feature.files.BackupOverview(
                    backups =
                        (1..6).map { index ->
                            FolderBackupEntity(
                                id = "backup-$index",
                                accountId = "account",
                                spaceId = "personal",
                                sourceTreeUri = "content://provider/tree/primary%3AFolder$index",
                                sourceDisplayName = "Folder $index",
                                destinationPath = "/Backups/Folder $index",
                                mediaType = "ALL",
                                wifiOnly = false,
                                chargingOnly = false,
                                deleteAfterUpload = false,
                            )
                        },
                    onManage = {},
                )
            }
        }

        composeRule.onNodeWithContentDescription("Active backup configurations").performScrollToIndex(5)
        composeRule.onNodeWithText("Folder 6").fetchSemanticsNode()
        composeRule.onNodeWithText("/Backups/Folder 6", substring = true).fetchSemanticsNode()
    }

    private fun browserRoborazziOptions() =
        RoborazziOptions(
            compareOptions =
                RoborazziOptions.CompareOptions(
                    resultValidator = { result ->
                        result.pixelDifferences.toFloat() / result.pixelCount <= 0.001f
                    },
                ),
        )
}
