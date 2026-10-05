package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class FileOperationConflictDialogTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun cancelConflictDoesNotConfirmKeepBoth() {
        var cancels = 0
        var keeps = 0
        compose.setContent {
            OpenCloudTheme {
                FileOperationControls(
                    state = stateWithConflict(),
                    place = {},
                    cancel = { cancels++ },
                    retry = {},
                    dismiss = {},
                    keepBothConflict = { keeps++ },
                )
            }
        }

        compose
            .onNodeWithText(
                "notes.txt already exists in this folder. Keep both using the name notes (1).txt, or cancel.",
                substring = true,
            ).assertExists()
        compose.onNodeWithText("Cancel").performClick()
        assertEquals(1, cancels)
        assertEquals(0, keeps)
    }

    @Test fun keepBothConfirmsTheShownNumberedName() {
        var cancels = 0
        var keeps = 0
        compose.setContent {
            OpenCloudTheme {
                FileOperationControls(
                    state = stateWithConflict(),
                    place = {},
                    cancel = { cancels++ },
                    retry = {},
                    dismiss = {},
                    keepBothConflict = { keeps++ },
                )
            }
        }

        compose.onNodeWithText("Keep both").performClick()
        assertEquals(1, keeps)
        assertEquals(0, cancels)
    }

    @Test fun placementActionsAreDisabledWhileRequestIsInFlight() {
        compose.setContent {
            OpenCloudTheme {
                FileOperationControls(
                    state = stateWithConflict().copy(placementBusy = true),
                    place = {},
                    cancel = {},
                    retry = {},
                    dismiss = {},
                    keepBothConflict = {},
                )
            }
        }

        compose.onNodeWithText("Copy here").assertIsNotEnabled()
        compose.onNodeWithText("Keep both").assertIsNotEnabled()
        compose.onNodeWithText("Cancel").assertIsNotEnabled()
    }

    private fun stateWithConflict(): FileBrowserUiState {
        val source =
            ResourceEntity(
                accountId = "account",
                spaceId = "space",
                remoteId = "file-id",
                parentId = null,
                path = "/notes.txt",
                name = "notes.txt",
                kind = ResourceKind.FILE,
                mimeType = "text/plain",
                sizeBytes = 12,
                eTag = null,
                modifiedAtEpochMillis = 0,
                createdAtEpochMillis = 0,
            )
        return FileBrowserUiState(
            clipboard = source,
            clipboardItems = listOf(source),
            placementConflict =
                FileOperationPlacementConflict(
                    source,
                    "space",
                    null,
                    moving = false,
                    suggestedName = "notes (1).txt",
                ),
        )
    }
}
