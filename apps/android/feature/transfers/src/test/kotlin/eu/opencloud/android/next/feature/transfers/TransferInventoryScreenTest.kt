package eu.opencloud.android.next.feature.transfers

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.database.TransferAccountActions
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferInventoryCounts
import eu.opencloud.android.next.core.database.TransferInventoryPage
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class TransferInventoryScreenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun historyWindowKeepsGlobalActionsAndUsesNativePageCallbacks() {
        var state by mutableStateOf(window(128))
        val pages = mutableListOf<Boolean>()
        var retryCalls = 0
        var cancelCalls = 0
        compose.setContent {
            OpenCloudTheme {
                TransfersScreen(
                    state = state,
                    selectedAccountId = "account",
                    onNavigateBack = {},
                    onRetry = {},
                    onCancel = {},
                    onResolveConflict = { _, _ -> },
                    onRetryAll = { retryCalls++ },
                    onClearAll = {},
                    onDismissError = {},
                    onCancelUploadConflicts = { cancelCalls++ },
                    onPage = { previous ->
                        pages += previous
                        state = window(if (previous) 128 else 256)
                    },
                )
            }
        }
        compose.onNodeWithText("129–256 of 400").assertIsDisplayed()
        compose.onNodeWithText("Retry eligible uploads").performClick()
        assertEquals(1, retryCalls)
        compose.onNodeWithText("Next").performClick()
        compose.onNodeWithText("257–384 of 400").assertIsDisplayed()
        compose.onNodeWithText("Previous").performClick()
        compose.runOnIdle { assertEquals(listOf(false, true), pages) }
        compose.onNodeWithContentDescription("Transfer actions").performClick()
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        compose.onNodeWithText("Cancel 4 conflicting uploads for this account?", substring = true).assertIsDisplayed()
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        assertEquals(1, cancelCalls)
        compose.runOnIdle { state = state.copy(loading = true) }
        compose.onNodeWithText("Next").assertIsNotEnabled()
        compose.onNodeWithText("Previous").assertIsNotEnabled()
    }

    @Test fun encryptedFolderTransfersUseTheEncryptedLabelWithoutExposingOpaquePaths() {
        val opaquePath = "opaque-vault/opaque-folder"
        val group =
            window(0).history.first().copy(
                id = "group",
                direction = "DOWNLOAD",
                state = "AWAITING_UNLOCK",
                offlinePin = true,
                locationKind = "VAULT_GROUP",
                displayName = "Encrypted offline folder",
                destinationPath = opaquePath,
            )
        compose.setContent {
            OpenCloudTheme {
                TransfersScreen(
                    state = TransfersUiState(active = listOf(group)),
                    selectedAccountId = "account",
                    onNavigateBack = {},
                    onRetry = {},
                    onCancel = {},
                    onResolveConflict = { _, _ -> },
                    onRetryAll = {},
                    onClearAll = {},
                    onDismissError = {},
                )
            }
        }
        compose.onNodeWithText("From: Encrypted destination").assertIsDisplayed()
        compose.onNodeWithText(opaquePath, substring = true).assertDoesNotExist()
    }

    private fun window(offset: Int): TransfersUiState {
        val entries =
            List(128) { index ->
                TransferEntity(
                    id = "history-${offset + index}",
                    accountId = "account",
                    spaceId = "space",
                    resourceId = null,
                    direction = "DOWNLOAD",
                    sourceUri = null,
                    destinationPath = "/history",
                    displayName = "saved-$index.txt",
                    mimeType = "text/plain",
                    bytesTotal = 10,
                    state = "SUCCEEDED",
                    createdAtEpochMillis = 0,
                    updatedAtEpochMillis = 0,
                )
            }
        val actions = TransferAccountActions(total = 400, uploadRetryCount = 3, uploadConflictCount = 4)
        return TransfersUiState(
            history = entries,
            actions = actions,
            page = TransferInventoryPage(offset, 400, entries, TransferInventoryCounts(3, 4, 393), actions),
        )
    }
}
