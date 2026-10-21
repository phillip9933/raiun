package eu.opencloud.android.next

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasAnyAncestor
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.isPopup
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.feature.transfers.TransfersScreen
import eu.opencloud.android.next.feature.transfers.TransfersUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode

@RunWith(RobolectricTestRunner::class)
@GraphicsMode(GraphicsMode.Mode.NATIVE)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class TransfersFilterInteractionTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun directionTypeAndStatusSelectionsFilterRowsAndResetRestoresThem() {
        render()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/transfer_filters.png")
        compose.onNodeWithText("Downloads").performClick().assertIsSelected()
        compose.onNodeWithText("holiday.jpg").assertDoesNotExist()
        compose.onNodeWithText("report.pdf").assertExists()
        compose.onNodeWithText("All file types").performClick()
        compose.onNode(hasText("Documents") and hasAnyAncestor(isPopup())).performClick()
        compose.onNodeWithText("Documents").assertIsSelected()
        compose.onNodeWithText("report.pdf").assertExists()
        compose.onNodeWithText("All statuses").performClick()
        compose.onNode(hasText("Succeeded") and hasAnyAncestor(isPopup())).performClick()
        compose.onNodeWithText("No matching transfers").assertExists()
        compose.onNodeWithText("Reset filters").performClick()
        compose.onNodeWithText("holiday.jpg").assertExists()
        compose.onNodeWithText("report.pdf").assertExists()
    }

    @Test fun customDateRangeDialogOpensAndCancelsWithoutChangingFilters() {
        render()
        compose.onNodeWithText("Any date").performClick()
        compose.onNode(hasText("Custom date range…") and hasAnyAncestor(isPopup())).performClick()
        compose.onNodeWithText("Filter by date started").assertExists()
        compose.onNodeWithText("Cancel").performClick()
        compose.onNodeWithText("Any date").assertExists()
        compose.onNodeWithText("holiday.jpg").assertExists()
        compose.onNodeWithText("report.pdf").assertExists()
    }

    private fun render() {
        compose.setContent {
            OpenCloudTheme {
                TransfersScreen(
                    state =
                        TransfersUiState(
                            active = listOf(transfer("upload", "holiday.jpg", "UPLOAD")),
                            failed = listOf(transfer("download", "report.pdf", "DOWNLOAD").copy(state = "FAILED")),
                        ),
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
    }

    private fun transfer(
        id: String,
        name: String,
        direction: String,
    ) = TransferEntity(
        id,
        "account",
        "space",
        null,
        direction,
        null,
        "/$name",
        name,
        null,
        10,
        createdAtEpochMillis = 1_700_000_000_000L,
        updatedAtEpochMillis = 1_700_000_000_000L,
    )
}
