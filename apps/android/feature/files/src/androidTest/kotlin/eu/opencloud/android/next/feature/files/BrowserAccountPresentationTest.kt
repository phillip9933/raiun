package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Real Android dialog windows exercise the account-epoch reset without accounts, credentials or network. */
@RunWith(AndroidJUnit4::class)
class BrowserAccountPresentationTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun accountRevisionDismissesRenameWithoutSubmitting() {
        val file = resource()
        var state by mutableStateOf(FileBrowserUiState(actionResource = file, accountRevision = 1))
        var renames = 0
        compose.setContent {
            Browser(
                state,
                onActions = { state = state.copy(actionResource = it) },
                onDismiss = { state = state.copy(actionResource = null) },
                onRename = { _, _ -> renames++ },
            )
        }
        val rename = compose.activity.getString(R.string.browser_rename)
        val save = compose.activity.getString(R.string.browser_save)
        compose
            .onNodeWithText(rename)
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(save).assertIsDisplayed()
        compose.runOnIdle { state = state.copy(accountRevision = 2, actionResource = null) }
        compose.onNodeWithText(save).assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, renames) }
    }

    @Test fun accountRevisionDismissesDetailsWithoutSubmittingRename() {
        val file = resource()
        var state by mutableStateOf(FileBrowserUiState(actionResource = file, accountRevision = 1))
        var renames = 0
        compose.setContent {
            Browser(
                state,
                onActions = { state = state.copy(actionResource = it) },
                onDismiss = { state = state.copy(actionResource = null) },
                onRename = { _, _ -> renames++ },
            )
        }
        val details = compose.activity.getString(R.string.browser_details)
        val versions = compose.activity.getString(R.string.file_versions_title)
        compose
            .onNodeWithText(details)
            .performScrollTo()
            .assertIsDisplayed()
            .performClick()
        compose.onNodeWithText(versions).performScrollTo().assertIsDisplayed()
        compose.runOnIdle { state = state.copy(accountRevision = 2, actionResource = null) }
        compose.onNodeWithText(versions).assertDoesNotExist()
        compose.runOnIdle { assertEquals(0, renames) }
    }

    @Composable
    @Suppress("LongMethod") // Explicit no-op callbacks preserve the actual browser action and dialog wiring.
    private fun Browser(
        state: FileBrowserUiState,
        onActions: (ResourceEntity) -> Unit,
        onDismiss: () -> Unit,
        onRename: (ResourceEntity, String) -> Unit,
    ) = OpenCloudTheme {
        FileBrowserScreen(
            accountId = "account",
            releaseVersion = "test",
            state = state,
            onSelectSpace = {},
            onOpen = {},
            onOpenWith = {},
            onNavigateUp = {},
            onSetLayout = {},
            onToggleSelection = {},
            onClearSelection = {},
            onDownloadSelection = {},
            onDeleteSelection = {},
            onShowActions = { it?.let(onActions) },
            onDismissActions = onDismiss,
            onCreateFolder = {},
            onCreateSpace = {},
            onRename = onRename,
            onMove = {},
            onCopy = {},
            onDelete = {},
            onUpload = {},
            onDownloadForOffline = {},
            onToggleFavorite = {},
            onResolveConflict = { _, _ -> },
            onClearMessage = {},
            onSearchQueryChange = {},
            onOpenTransfers = {},
            onOpenDeletedFiles = {},
            onOpenSettings = {},
            onOpenAccount = {},
            onShareResource = {},
        )
    }

    private fun resource() =
        ResourceEntity(
            "account",
            "space",
            "file",
            null,
            "/note.txt",
            "note.txt",
            ResourceKind.FILE,
            "text/plain",
            1,
            "tag",
            1,
            1,
        )
}
