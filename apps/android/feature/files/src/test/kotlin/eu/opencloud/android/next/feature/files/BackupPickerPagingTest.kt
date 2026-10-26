package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class BackupPickerPagingTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun `empty shared folder window remains pageable and read only target cannot be selected`() {
        val state =
            FileBrowserUiState(
                backupPickerDestination =
                    BackupDestination(
                        "scope",
                        "/Photos",
                        "SHARED_FOLDER",
                        "share",
                        "photos",
                        "Photos",
                    ),
                backupPickerPage = BackupPickerPageState(offset = 256, total = 300, pageSize = 256),
                backupPickerCanSelect = false,
            )
        var pagedPrevious = false
        compose.setContent {
            OpenCloudTheme {
                BackupDestinationPickerDialog(
                    state = state,
                    onDismiss = {},
                    onOpenSpace = {},
                    onOpenShare = {},
                    onOpenFolder = {},
                    onOpenSharedFolder = {},
                    onNavigateUp = {},
                    onRetry = {},
                    onCreateFolder = {},
                    onSelect = {},
                    onPage = { pagedPrevious = it },
                )
            }
        }
        compose.onNodeWithText("Previous").assertIsDisplayed().performClick()
        compose.onNodeWithText("257–300 of 300").assertIsDisplayed()
        compose.onNodeWithText("Select this folder").assertIsNotEnabled()
        compose.onNodeWithText("No folders here").assertDoesNotExist()
        compose.runOnIdle { assertEquals(true, pagedPrevious) }
    }
}
