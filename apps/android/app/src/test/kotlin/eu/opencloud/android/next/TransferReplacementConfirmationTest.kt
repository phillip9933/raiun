package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isDialog
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.transfers.TransferConflictDecision
import eu.opencloud.android.next.feature.transfers.TransfersScreen
import eu.opencloud.android.next.feature.transfers.TransfersUiState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35], qualifiers = "w360dp-h800dp")
class TransferReplacementConfirmationTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun replacementRequiresConfirmationAndCancelPreservesConflict() {
        val decisions = mutableListOf<TransferConflictDecision>()
        render("SPACE", decisions)
        compose.onNodeWithText("Overwrite cloud copy").performClick()
        compose.onNodeWithText("Replace existing file?").assertExists()
        compose
            .onNodeWithText(
                "Replace “report.txt” at /Documents/report.txt? Existing contents may be overwritten. " +
                    "Raiun cannot undo this replacement.",
            ).assertExists()
        assertEquals(emptyList<TransferConflictDecision>(), decisions)
        compose.onNode(hasText("Cancel") and hasAnyAncestor(isDialog())).performClick()
        assertEquals(emptyList<TransferConflictDecision>(), decisions)
        compose.onNodeWithText("Overwrite cloud copy").performClick()
        compose.onNode(hasText("Overwrite cloud copy") and hasAnyAncestor(isDialog())).performClick()
        assertEquals(listOf(TransferConflictDecision.REPLACE), decisions)
    }

    @Test fun sharedFolderNeverOffersReplacement() {
        render("SHARED_FOLDER", mutableListOf())
        compose.onNodeWithText("Overwrite cloud copy").assertDoesNotExist()
    }

    @Test fun vaultNeverOffersReplacement() {
        render("VAULT", mutableListOf())
        compose.onNodeWithText("Overwrite cloud copy").assertDoesNotExist()
    }

    private fun render(
        locationKind: String,
        decisions: MutableList<TransferConflictDecision>,
    ) {
        val transfer =
            TransferEntity(
                "conflict",
                "account",
                "space",
                null,
                "UPLOAD",
                null,
                "/Documents/report.txt",
                "report.txt",
                null,
                10,
                createdAtEpochMillis = 1_700_000_000_000L,
                updatedAtEpochMillis = 1_700_000_000_000L,
            ).copy(state = "CONFLICT", locationKind = locationKind)
        compose.setContent {
            OpenCloudTheme {
                TransfersScreen(
                    state = TransfersUiState(failed = listOf(transfer)),
                    onNavigateBack = {},
                    onRetry = {},
                    onCancel = {},
                    onResolveConflict = { _, decision -> decisions += decision },
                    onRetryAll = {},
                    onClearAll = {},
                    onDismissError = {},
                )
            }
        }
    }
}
