package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Executes the paging expressions against the device SQLite rather than Robolectric SQLite. */
@RunWith(AndroidJUnit4::class)
class ResourceDirectoryPagingAndroidTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var paging: ResourceDirectoryPaging
    private val account = AccountEntity("paging", "https://example.test", "synthetic", "Synthetic", "BASIC", false)
    private val space = SpaceEntity("paging", "space", "Personal", "personal", null, null, "root", null, null, null)

    @Before fun open() =
        runBlocking {
            val context = InstrumentationRegistry.getInstrumentation().targetContext
            database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
            paging = ResourceDirectoryPaging(database)
            database.accountDao().upsert(account)
            database.spaceDao().upsertAll(listOf(space))
        }

    @After fun close() = database.close()

    @Test fun sixHundredRowsUseGloballySortedBoundedWindowsWithMergedRoots() =
        runBlocking {
            val rows = (0 until 600).map(::resource)
            database.resourceDao().insertAll(rows)
            val roots = listOf(DirectoryOverlay("early", "aaa"), DirectoryOverlay("middle", "item0150.pdf"))
            for (sort in DirectorySort.entries) {
                for (ascending in listOf(true, false)) {
                    val expected = rows.map { expected(it) } + roots.map { Expected(it.id, it.name, true, 0, true) }
                    val ordered = expected.sortedWith(comparator(sort, ascending)).map { it.id }
                    val actual = mutableListOf<String>()
                    var offset = 0
                    while (true) {
                        val page = paging.load("paging", "space", null, offset, sort, ascending, true, roots)
                        assertEquals(602, page.total)
                        assertEquals(offset, page.offset)
                        assertTrue(page.entries.size in 1..128)
                        actual += page.entries.map { it.resource?.remoteId ?: requireNotNull(it.overlayId) }
                        offset += page.entries.size
                        if (!page.hasNext) break
                    }
                    assertEquals("$sort ascending=$ascending", ordered, actual)
                    assertEquals(602, actual.distinct().size)
                }
            }
        }

    @Test fun leadingSlashExclusionsHiddenNamesAndRevokedAccountsCannotLeakRows() =
        runBlocking {
            database.resourceDao().insertAll(
                listOf(
                    resource(1),
                    resource(2).copy(name = ".hidden", path = "/.hidden"),
                    resource(3).copy(name = "secret", path = "/private/secret"),
                ),
            )
            database.vaultExclusionDao().record(VaultExclusion("paging", "space", "/private/"))
            assertEquals(listOf("1"), load().entries.map { it.resource?.remoteId })
            assertEquals(2, load(showHidden = true).total)
            val updates = Channel<Int>(Channel.UNLIMITED)
            val observer =
                launch(Dispatchers.IO) { paging.invalidations("paging", "space", null).collect { updates.send(it) } }
            try {
                withTimeout(10_000) { updates.receive() }
                database.spaceDao().upsertAll(listOf(space.copy(isDisabled = true)))
                withTimeout(10_000) { updates.receive() }
                assertFalse(load().accessible)
                assertTrue(load().entries.isEmpty())
                database.spaceDao().upsertAll(listOf(space))
                assertTrue(load().accessible)
                database.accountDao().upsert(account.copy(isActive = false))
                assertFalse(load().accessible)
                assertTrue(load().entries.isEmpty())
            } finally {
                observer.cancelAndJoin()
                updates.close()
            }
        }

    private suspend fun load(showHidden: Boolean = false) =
        paging.load("paging", "space", null, 0, DirectorySort.Name, true, showHidden, emptyList())

    private fun resource(index: Int): ResourceEntity {
        val name = "item${index.toString().padStart(4, '0')}.${if (index % 2 == 0) "pdf" else "txt"}"
        return ResourceEntity(
            "paging",
            "space",
            index.toString(),
            null,
            "/$name",
            name,
            if (index % 3 == 0) ResourceKind.FOLDER else ResourceKind.FILE,
            "text/plain",
            index.toLong(),
            null,
            index.toLong(),
            index.toLong(),
        )
    }

    private data class Expected(
        val id: String,
        val name: String,
        val folder: Boolean,
        val number: Long,
        val overlay: Boolean,
    )

    private fun expected(row: ResourceEntity) =
        Expected(row.remoteId, row.name, row.kind == ResourceKind.FOLDER, row.sizeBytes, false)

    private fun comparator(
        sort: DirectorySort,
        ascending: Boolean,
    ): Comparator<Expected> {
        val primary =
            when (sort) {
                DirectorySort.Name -> compareBy<Expected> { it.name.lowercase() }
                DirectorySort.Type -> compareBy<Expected> { it.name.substringAfterLast('.', "").lowercase() }
                else -> compareBy<Expected> { it.number }
            }.thenBy { it.name.lowercase() }
        val ordered = if (ascending) primary else primary.reversed()
        return compareBy<Expected> { !it.folder }.then(ordered).thenBy { it.overlay }.thenBy { it.id }
    }
}
