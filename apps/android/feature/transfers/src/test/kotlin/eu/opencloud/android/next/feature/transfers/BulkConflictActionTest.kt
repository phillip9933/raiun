package eu.opencloud.android.next.feature.transfers

import androidx.activity.ComponentActivity
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class BulkConflictActionTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun menuActionRequiresConfirmationAndCancelLeavesRowsUntouched() {
        var bulkCalls = 0
        render(TransfersUiState(failed = listOf(conflict(), conflict().copy(id = "vault", locationKind = "VAULT")))) {
            bulkCalls++
        }
        compose.onNodeWithContentDescription("Transfer actions").performClick()
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        compose.onNodeWithText("Cancel 2 conflicting uploads for this account?", substring = true).assertExists()
        val cancelButtons = compose.onAllNodesWithText("Cancel")
        cancelButtons[cancelButtons.fetchSemanticsNodes().lastIndex].performClick()
        assertEquals(0, bulkCalls)
        compose.onAllNodesWithText("notes.txt").assertCountEquals(2)
        compose.onNodeWithContentDescription("Transfer actions").performClick()
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        assertEquals(1, bulkCalls)
    }

    @Test fun pendingOperationDisablesIndividualConflictActions() {
        compose.setContent {
            OpenCloudTheme {
                TransferConflictActions(locationKind = "", enabled = false, onConflict = {})
            }
        }
        compose.onNodeWithText("Overwrite cloud copy").assertIsNotEnabled()
        compose.onNodeWithText("Rename new copy").assertIsNotEnabled()
        compose.onNodeWithText("Cancel").assertIsNotEnabled()
    }

    @Test fun targetSelectionIncludesVaultOnlyForSelectedAccount() {
        val selected = conflict()
        assertEquals(
            listOf("conflict", "vault"),
            bulkUploadConflictTargets(
                listOf(
                    selected,
                    selected.copy(id = "vault", locationKind = "VAULT"),
                    selected.copy(id = "other", accountId = "other"),
                    selected.copy(id = "download", direction = "DOWNLOAD"),
                    selected.copy(id = "failed", state = "FAILED"),
                ),
                "account",
            ).map { it.id },
        )
    }

    @Test fun switchingAccountsClosesTheOldConfirmation() {
        val selectedAccount = mutableStateOf("account")
        var bulkCalls = 0
        compose.setContent {
            OpenCloudTheme {
                TransfersScreen(
                    state =
                        TransfersUiState(
                            failed = listOf(conflict(), conflict().copy(id = "other", accountId = "other")),
                        ),
                    selectedAccountId = selectedAccount.value,
                    onNavigateBack = {},
                    onRetry = {},
                    onCancel = {},
                    onResolveConflict = { _, _ -> },
                    onRetryAll = {},
                    onClearAll = {},
                    onDismissError = {},
                    onCancelUploadConflicts = { bulkCalls++ },
                )
            }
        }
        compose.onNodeWithContentDescription("Transfer actions").performClick()
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        compose.onNodeWithText("Cancel conflicting uploads?").assertExists()
        compose.runOnIdle { selectedAccount.value = "other" }
        compose.onNodeWithText("Cancel conflicting uploads?").assertDoesNotExist()
        assertEquals(0, bulkCalls)
    }

    private fun render(
        state: TransfersUiState,
        onBulk: () -> Unit,
    ) {
        compose.setContent {
            OpenCloudTheme {
                TransfersScreen(
                    state = state,
                    selectedAccountId = "account",
                    onNavigateBack = {},
                    onRetry = {},
                    onCancel = {},
                    onResolveConflict = { _, _ -> },
                    onRetryAll = {},
                    onClearAll = {},
                    onDismissError = {},
                    onCancelUploadConflicts = onBulk,
                )
            }
        }
    }

    private fun conflict() =
        TransferEntity(
            "conflict",
            "account",
            "space",
            null,
            "UPLOAD",
            null,
            "/notes.txt",
            "notes.txt",
            null,
            10,
            state = "CONFLICT",
            createdAtEpochMillis = 0,
            updatedAtEpochMillis = 0,
        )
}
