package eu.opencloud.android.next.ui

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Surface
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasScrollToIndexAction
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToIndex
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.files.BackupDraft
import eu.opencloud.android.next.feature.files.FolderBackupSettingsContent
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class BackupExclusionsDialogAndroidTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test
    fun lightDialogRendersAndAppliesIndividualRows() {
        var saved: BackupDraft? = null
        showEditor(darkTheme = false) { saved = it }

        openExclusions()
        compose.onNodeWithText("*.tmp").assertIsDisplayed()
        saveScreenshot("backup-exclusions-light.png")

        compose.onNodeWithContentDescription("Add exclusion").performClick()
        compose.onNodeWithText("Pattern 4").performTextInput("logs/**")
        compose.onNode(hasScrollToIndexAction()).performScrollToIndex(0)
        compose.onNodeWithContentDescription("Remove pattern 1").performClick()
        compose.onNodeWithText("Done").performClick()
        compose.onNodeWithText("Save").performClick()
        assertEquals(".thumbnail\nCache/\nlogs/**", saved?.exclusionPatterns)

        openExclusions()
        compose.onNodeWithText(".thumbnail").performTextReplacement("discarded")
        compose.onAllNodesWithText("Cancel")[1].performClick()
        compose.onNodeWithText("Save").performClick()
        assertEquals(".thumbnail\nCache/\nlogs/**", saved?.exclusionPatterns)
    }

    @Test
    fun darkDialogRenders() {
        showEditor(darkTheme = true) {}
        openExclusions()
        compose.onNodeWithText("*.tmp").assertIsDisplayed()
        saveScreenshot("backup-exclusions-dark.png")
    }

    private fun showEditor(
        darkTheme: Boolean,
        onSave: (BackupDraft) -> Unit,
    ) {
        compose.setContent {
            OpenCloudTheme(darkTheme = darkTheme) {
                Surface(Modifier.fillMaxSize()) {
                    FolderBackupSettingsContent(
                        backups = emptyList(),
                        initialBackup =
                            FolderBackupEntity(
                                id = "backup",
                                accountId = "account",
                                spaceId = "personal",
                                sourceTreeUri = "content://test/tree/camera",
                                sourceDisplayName = "Camera",
                                destinationPath = "/Pictures",
                                mediaType = "ALL",
                                wifiOnly = true,
                                chargingOnly = false,
                                deleteAfterUpload = false,
                                exclusionPatterns = "*.tmp\n.thumbnail\nCache/",
                            ),
                        onDismiss = {},
                        onAdd = onSave,
                        onDelete = {},
                    )
                }
            }
        }
    }

    private fun openExclusions() {
        compose.onNodeWithText("Manage exclusions").performScrollTo().performClick()
    }

    private fun saveScreenshot(fileName: String) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val directory =
            InstrumentationRegistry.getArguments().getString("additionalTestOutputDir")?.let(::File)
                ?: checkNotNull(instrumentation.targetContext.getExternalFilesDir(null))
        check(directory.isDirectory || directory.mkdirs())
        val bitmap = checkNotNull(instrumentation.uiAutomation.takeScreenshot())
        File(directory, fileName).outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
        bitmap.recycle()
    }
}
