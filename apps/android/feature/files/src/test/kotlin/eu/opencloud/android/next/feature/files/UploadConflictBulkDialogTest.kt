package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createAndroidComposeRule
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
@Config(sdk = [35])
class UploadConflictBulkDialogTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun cancellationRequiresConfirmationAndDismissingItKeepsConflicts() {
        var bulkCalls = 0
        var individualCalls = 0
        compose.setContent {
            OpenCloudTheme {
                ConflictResolutionDialog(
                    conflict = conflict(),
                    count = 2,
                    busy = false,
                    onDecision = { individualCalls++ },
                    onCancelAll = { bulkCalls++ },
                )
            }
        }
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        compose.onNodeWithText("Cancel 2 conflicting uploads for this account?", substring = true).assertExists()
        compose.onNodeWithText("Keep conflicts").performClick()
        assertEquals(0, bulkCalls)
        assertEquals(0, individualCalls)
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        compose.onNodeWithText("Cancel all conflicting uploads").performClick()
        assertEquals(1, bulkCalls)
        assertEquals(0, individualCalls)
    }

    @Test fun pendingCancellationDisablesAllConflictActions() {
        compose.setContent {
            OpenCloudTheme {
                ConflictResolutionDialog(
                    conflict = conflict(),
                    count = 1,
                    busy = true,
                    onDecision = {},
                    onCancelAll = {},
                )
            }
        }
        compose.onNodeWithText("Cancel all conflicting uploads").assertIsNotEnabled()
        compose.onNodeWithText("Cancel upload").assertIsNotEnabled()
    }

    @Test fun targetListIsLimitedToUploadConflictsForSelectedAccount() {
        val selected = conflict()
        assertEquals(
            listOf(selected.id, "vault"),
            bulkUploadConflictTargets(
                listOf(
                    selected,
                    selected.copy(id = "vault", locationKind = "VAULT"),
                    selected.copy(id = "download", direction = "DOWNLOAD"),
                    selected.copy(id = "other", accountId = "other"),
                    selected.copy(id = "failed", state = "FAILED"),
                ),
                "account",
            ).map { it.id },
        )
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
