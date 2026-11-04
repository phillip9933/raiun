package eu.opencloud.android.next.feature.files

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferInventory
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
class BrowserTransferSummaryTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun unknownRepresentativeStaysVisibleAndOpensTransfersWithoutExposingRawState() =
        runBlocking {
            val database = Room.inMemoryDatabaseBuilder(compose.activity, FileBrowserDatabase::class.java).build()
            try {
                database.accountDao().upsert(
                    AccountEntity("account", "https://example.test", "user", "User", "BASIC", false),
                )
                val failed = transfer("old-failed", "FAILED", 1)
                val unknown = transfer("unknown", "FUTURE_PRIVATE_MARKER", 2).copy(error = "unsafe row detail")
                listOf(failed, unknown).forEach { database.transferDao().insert(it) }
                val representative = TransferInventory(database).overview("account").representative
                assertEquals(unknown, representative)
                assertEquals(representative, legacyTransferOverview(listOf(failed, unknown), "account").representative)
                var opened = 0
                compose.setContent {
                    OpenCloudTheme {
                        TransferSummary(listOfNotNull(representative)) { opened++ }
                    }
                }
                compose.onNodeWithText("Transfer needs attention: unknown.txt").assertIsDisplayed().performClick()
                compose.onNodeWithText("FUTURE_PRIVATE_MARKER", substring = true).assertDoesNotExist()
                compose.onNodeWithText("unsafe row detail", substring = true).assertDoesNotExist()
                compose.runOnIdle { assertEquals(1, opened) }
            } finally {
                database.close()
            }
        }

    @Test fun fallbackUsesDatabasePriorityAndNewestAttentionInsteadOfInputOrder() {
        val failed = transfer("failed", "FAILED", 1)
        val unknown = transfer("unknown", "future", 2)
        val queued = transfer("queued", "QUEUED", 0)
        val retry = transfer("retry", "RETRY", 3)
        val running = transfer("running", "RUNNING", 0)
        assertEquals(unknown, legacyTransferOverview(listOf(failed, unknown), "account").representative)
        assertEquals(retry, legacyTransferOverview(listOf(unknown, queued, retry), "account").representative)
        assertEquals(running, legacyTransferOverview(listOf(retry, running, unknown), "account").representative)
        val tieA = transfer("a", "FAILED", 10)
        val tieB = transfer("b", "future", 10)
        assertEquals(tieB, legacyTransferOverview(listOf(tieA, tieB), "account").representative)
        assertNull(
            legacyTransferOverview(
                listOf(transfer("awaiting", "AWAITING_UNLOCK", 20), transfer("done", "SUCCEEDED", 30)),
                "account",
            ).representative,
        )
    }

    private fun transfer(
        id: String,
        state: String,
        created: Long,
    ) = TransferEntity(
        id = id,
        accountId = "account",
        spaceId = "space",
        resourceId = null,
        direction = "UPLOAD",
        sourceUri = null,
        destinationPath = "/$id.txt",
        displayName = "$id.txt",
        mimeType = "text/plain",
        bytesTotal = 100,
        state = state,
        createdAtEpochMillis = created,
        updatedAtEpochMillis = created,
    )
}
