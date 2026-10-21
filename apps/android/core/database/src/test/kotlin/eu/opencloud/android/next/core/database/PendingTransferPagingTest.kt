package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.room.withTransaction
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class PendingTransferPagingTest {
    @Test fun `recovery pages every pending intent once and skips terminal history`() =
        runTest {
            val database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            try {
                val records =
                    (0 until 700).map { number ->
                        TransferEntity(
                            id = number.toString().padStart(4, '0'),
                            accountId = "synthetic-account",
                            spaceId = "synthetic-space",
                            resourceId = null,
                            direction = "UPLOAD",
                            sourceUri = "content://synthetic/$number",
                            destinationPath = "/$number",
                            displayName = "$number",
                            mimeType = null,
                            bytesTotal = 1,
                            state =
                                if (number % 5 ==
                                    0
                                ) {
                                    "SUCCEEDED"
                                } else {
                                    listOf("QUEUED", "RUNNING", "RETRY")[number % 3]
                                },
                            createdAtEpochMillis = 1,
                            updatedAtEpochMillis = 1,
                        )
                    }
                database.withTransaction { records.forEach { database.transferDao().insert(it) } }
                val store = FileBrowserStore(database)
                val recovered = mutableListOf<String>()
                var cursor = ""
                while (true) {
                    val page = store.pendingTransferPage(cursor)
                    if (page.isEmpty()) break
                    assertTrue(page.size <= 256)
                    assertTrue(page.all { it.id > cursor })
                    recovered += page.map { it.id }
                    cursor = page.last().id
                }
                assertEquals(records.filterNot { it.state == "SUCCEEDED" }.map { it.id }, recovered)
            } finally {
                database.close()
            }
        }
}
