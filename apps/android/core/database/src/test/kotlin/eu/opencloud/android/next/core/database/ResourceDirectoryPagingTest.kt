package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.room.withTransaction
import eu.opencloud.android.next.core.model.ResourceKind
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
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class ResourceDirectoryPagingTest {
    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).build()
    private val paging = ResourceDirectoryPaging(database)
    private val account = AccountEntity("account", "https://example.test", "user", "User", "BASIC", false)
    private val space = SpaceEntity("account", "space", "Personal", "personal", null, null, "root", null, null, null)

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(account)
            database.spaceDao().upsertAll(listOf(space))
        }

    @After fun close() = database.close()

    @Test fun `remembered roots suppress stale ordinary identities and paths without persistent vault exclusions`() =
        runBlocking {
            database.resourceDao().insertAll(
                listOf(
                    resource("old-id", "Old name", true),
                    resource("stale-id", "Renamed", true).copy(path = "/Secret.vault/"),
                    resource("normal", "Normal"),
                ),
            )
            val roots = listOf(DirectoryOverlay("locked", "Secret.vault", "old-id", "Secret.vault"))
            val page = load(0, overlays = roots)
            assertEquals(2, page.total)
            assertEquals(listOf("normal"), page.entries.mapNotNull { it.resource?.remoteId })
            assertEquals(listOf("locked"), page.entries.mapNotNull { it.overlayId })
            // Per-load temporary keys must not affect an independent subsequent snapshot.
            assertEquals(3, load(0).total)
        }

    @Test fun `more than nine hundred ninety nine remembered roots avoid SQLite bind limits and merge exactly once`() =
        runBlocking {
            val roots =
                (0 until 1100).map { number ->
                    DirectoryOverlay("root$number", "vault$number", "id$number", "/vault$number")
                }
            database.resourceDao().insertAll(listOf(resource("id1099", "Stale", true), resource("plain", "ZZZ", true)))
            val page = load(1024, overlays = roots)
            assertEquals(1101, page.total)
            assertEquals(77, page.entries.size)
            assertEquals(
                77,
                page.entries
                    .map { it.resource?.remoteId ?: it.overlayId }
                    .toSet()
                    .size,
            )
            assertFalse(page.entries.any { it.resource?.remoteId == "id1099" })
        }

    @Test fun `large directories load bounded windows without materializing all entries`() =
        runBlocking {
            val start = System.nanoTime()
            database.withTransaction {
                database.openHelper.writableDatabase.execSQL(
                    "WITH RECURSIVE sequence(n) AS (SELECT 0 UNION ALL SELECT n + 1 FROM sequence WHERE n < 100000) " +
                        "INSERT INTO resources (accountId, spaceId, remoteId, parentId, path, name, kind, mimeType, " +
                        "sizeBytes, eTag, modifiedAtEpochMillis, createdAtEpochMillis, " +
                        "isFavorite, hasLocalCopy, localPath, offlinePinned) " +
                        "SELECT 'account', 'space', printf('%06d', n), NULL, printf('file%06d.txt', n), " +
                        "printf('file%06d.txt', n), 'FILE', 'text/plain', n, NULL, n, n, 0, 0, NULL, 0 FROM sequence",
                )
            }
            val seeded = System.nanoTime()
            for (offset in listOf(0, 49_920, 99_968)) {
                val windowStart = System.nanoTime()
                val page = load(offset)
                assertEquals(100_001, page.total)
                assertTrue(page.entries.size in 1..128)
                assertEquals(
                    "file${offset.toString().padStart(6, '0')}.txt",
                    page.entries
                        .first()
                        .resource
                        ?.name,
                )
                assertEquals(minOf(128, 100_001 - offset), page.entries.size)
                println(
                    "ordinary-100001 offset=$offset rows=${page.entries.size} millis=${(System.nanoTime() - windowStart) / 1_000_000}",
                )
            }
            val descending = load(49_920, DirectorySort.Size, false)
            assertEquals(
                50_080L,
                descending.entries
                    .first()
                    .resource
                    ?.sizeBytes,
            )
            assertEquals(128, descending.entries.size)
            val mixedStart = System.nanoTime()
            val roots =
                (0 until 1_100).map {
                    DirectoryOverlay("root-$it", "vault${it.toString().padStart(4, '0')}")
                }
            val mixed = load(1_024, overlays = roots)
            assertEquals(101_101, mixed.total)
            assertEquals(128, mixed.entries.size)
            assertEquals(76, mixed.entries.count { it.overlayId != null })
            assertEquals(
                "file000000.txt",
                mixed.entries
                    .first { it.resource != null }
                    .resource
                    ?.name,
            )
            println("mixed-100001 roots=1100 rows=128 millis=${(System.nanoTime() - mixedStart) / 1_000_000}")
            println(
                "ordinary-100001 seedMillis=${(seeded - start) / 1_000_000} totalMillis=${(System.nanoTime() - start) / 1_000_000}",
            )
        }

    @Test fun `all global sort orders traverse bounded windows with locked roots at exact insertion ranks`() =
        runBlocking {
            val rows =
                (0 until 601).map { number ->
                    resource(
                        number.toString(),
                        "item${number.toString().padStart(4, '0')}.${if (number % 2 == 0) "txt" else "pdf"}",
                        number % 3 == 0,
                    ).copy(
                        sizeBytes = number.toLong(),
                        modifiedAtEpochMillis = number.toLong(),
                        createdAtEpochMillis =
                            600L - number,
                    )
                }
            database.withTransaction { database.resourceDao().insertAll(rows) }
            val roots =
                listOf(
                    DirectoryOverlay("vault-a", "item0000.txt"),
                    DirectoryOverlay("vault-b", "item0127.pdf"),
                    DirectoryOverlay("vault-c", "zz.vault"),
                )
            for (sort in DirectorySort.entries) {
                for (ascending in listOf(true, false)) {
                    val expected =
                        (
                            rows.map { ResourceDirectoryItem(resource = it) } +
                                roots.map { ResourceDirectoryItem(overlayId = it.id) }
                        ).sortedWith(expectedComparator(sort, ascending, roots))
                    val actual = mutableListOf<ResourceDirectoryItem>()
                    var offset = 0
                    do {
                        val page = load(offset, sort, ascending, roots)
                        assertTrue(page.entries.size <= RESOURCE_DIRECTORY_PAGE_SIZE)
                        assertEquals(604, page.total)
                        actual += page.entries
                        offset += RESOURCE_DIRECTORY_PAGE_SIZE
                    } while (page.hasNext)
                    assertEquals("$sort $ascending", expected, actual)
                    assertEquals(604, actual.map { it.resource?.remoteId ?: it.overlayId }.toSet().size)
                }
            }
        }

    @Test fun `hidden filtering vault exclusions and parent account space boundaries apply before page counts`() =
        runBlocking {
            val rows =
                listOf(
                    resource("plain", "Visible", true),
                    resource("hidden", ".hidden", true),
                    resource("vault", "Secret.vault", true),
                    resource("nested", "Nested").copy(parentId = "elsewhere"),
                    resource("other", "Other").copy(accountId = "other"),
                )
            database.resourceDao().insertAll(rows)
            database.vaultExclusionDao().record(VaultExclusion("account", "space", "/Secret.vault"))
            val roots =
                listOf(DirectoryOverlay("locked", "Secret.vault"), DirectoryOverlay("hidden-locked", ".locked.vault"))
            val hidden = load(0, overlays = roots)
            assertEquals(2, hidden.total)
            assertEquals(listOf("locked"), hidden.entries.mapNotNull { it.overlayId })
            assertEquals(listOf("plain"), hidden.entries.mapNotNull { it.resource?.remoteId })
            val all = paging.load("account", "space", null, 0, DirectorySort.Name, true, true, roots)
            assertEquals(4, all.total)
            assertFalse(all.entries.any { it.resource?.remoteId == "vault" })
        }

    @Test fun `shrunk directory clamps a stale offset within the same snapshot and empty roots do not invent a page`() =
        runBlocking {
            val rows = (0 until 270).map { resource("$it", "file$it") }
            database.resourceDao().insertAll(rows)
            assertEquals(256, load(256).offset)
            database.withTransaction { rows.drop(9).forEach { database.resourceDao().delete(it) } }
            val shrunk = load(256)
            assertEquals(0, shrunk.offset)
            assertEquals(9, shrunk.entries.size)
            assertFalse(shrunk.hasNext)
            database.resourceDao().deleteForAccount("account")
            assertEquals(ResourceDirectoryPage(0, 0, emptyList()), load(999))
        }

    @Test fun `leading slashes nested vault paths and wildcard characters remain literal exclusions`() =
        runBlocking {
            database.resourceDao().insertAll(
                listOf(
                    resource("root", "Secret.vault", true),
                    resource("nested", "Nested").copy(path = "/Secret.vault/sub/content"),
                    resource("wild", "Percent").copy(path = "/%_vault/enc-content"),
                    resource("sibling", "Sibling").copy(path = "/%xvault/enc-content"),
                    resource("prefix", "Prefix").copy(path = "/Secret.vault-other/content"),
                ),
            )
            database.vaultExclusionDao().record(VaultExclusion("account", "space", "/Secret.vault"))
            database.vaultExclusionDao().record(VaultExclusion("account", "space", "/%_vault"))
            assertEquals(setOf("sibling", "prefix"), load(0).entries.mapNotNull { it.resource?.remoteId }.toSet())
            database.vaultExclusionDao().record(VaultExclusion("account", "space", "/"))
            assertEquals(0, load(0).total)
        }

    @Test fun `access loss suppresses both ordinary pages and independent locked roots`() =
        runBlocking {
            database.resourceDao().insertAll(listOf(resource("row", "Row")))
            val roots = listOf(DirectoryOverlay("locked", "Locked.vault"))
            database.accountDao().upsert(account.copy(isActive = false))
            assertEquals(ResourceDirectoryPage(0, 0, emptyList(), false), load(0, overlays = roots))
            database.accountDao().upsert(account)
            database.spaceDao().upsertAll(listOf(space.copy(isDisabled = true)))
            assertFalse(load(0, overlays = roots).accessible)
            database.spaceDao().upsertAll(listOf(space.copy(isDeleted = true)))
            assertFalse(load(0, overlays = roots).accessible)
        }

    @Test fun `invalidation emits same count metadata updates and account space exclusion changes`() =
        runBlocking {
            database.resourceDao().insertAll(listOf(resource("row", "Before")))
            val events = Channel<Int>(Channel.UNLIMITED)
            val job = launch { paging.invalidations("account", "space", null).collect { events.send(it) } }

            suspend fun next() = withTimeout(10_000) { events.receive() }
            try {
                assertEquals(1, next())
                database.resourceDao().upsert(resource("row", "After"))
                assertEquals(1, next())
                assertEquals(
                    "After",
                    load(0)
                        .entries
                        .single()
                        .resource
                        ?.name,
                )
                database.spaceDao().upsertAll(listOf(space.copy(isDisabled = true)))
                next()
                assertFalse(load(0).accessible)
                database.spaceDao().upsertAll(listOf(space))
                next()
                database.vaultExclusionDao().record(VaultExclusion("account", "space", "After"))
                next()
                assertEquals(0, load(0).total)
                database.accountDao().upsert(account.copy(isActive = false))
                next()
                assertFalse(load(0).accessible)
            } finally {
                job.cancel()
            }
        }

    @Test fun `folder pickers exclude locked roots and files before counting windows`() =
        runBlocking {
            database.resourceDao().insertAll(
                listOf(
                    resource("folder", "Plain", true),
                    resource("file", "file.txt"),
                    resource("vault", "Secret.vault", true),
                ),
            )
            val roots = listOf(DirectoryOverlay("locked", "Secret.vault", "vault", "/Secret.vault"))
            val page =
                paging.load(
                    "account",
                    "space",
                    null,
                    0,
                    DirectorySort.Name,
                    true,
                    false,
                    roots,
                    onlyFolders = true,
                    includeOverlays = false,
                )
            assertEquals(1, page.total)
            assertEquals(
                "folder",
                page.entries
                    .single()
                    .resource
                    ?.remoteId,
            )
            assertTrue(page.entries.none { it.overlayId != null })
        }

    @Test fun `Unicode roots and resources share one ordering`() =
        runBlocking {
            database.resourceDao().insertAll(
                listOf(resource("one", "Ä", true), resource("two", "Z", true), resource("three", "a", true)),
            )
            val roots =
                listOf(
                    DirectoryOverlay("root-1", "ä"),
                    DirectoryOverlay("root-2", "A"),
                    DirectoryOverlay("root-3", "😀"),
                )
            val page = load(0, overlays = roots)
            val names = page.entries.map { item -> item.resource?.name ?: roots.first { it.id == item.overlayId }.name }
            assertEquals(listOf("a", "A", "Z", "Ä", "ä", "😀"), names)
        }

    private suspend fun load(
        offset: Int,
        sort: DirectorySort = DirectorySort.Name,
        ascending: Boolean = true,
        overlays: List<DirectoryOverlay> = emptyList(),
    ) = paging.load("account", "space", null, offset, sort, ascending, false, overlays)

    private fun resource(
        id: String,
        name: String,
        folder: Boolean = false,
    ) = ResourceEntity(
        "account",
        "space",
        id,
        null,
        "/$name",
        name,
        if (folder) ResourceKind.FOLDER else ResourceKind.FILE,
        "text/plain",
        1,
        null,
        1,
        1,
    )

    private fun expectedComparator(
        sort: DirectorySort,
        ascending: Boolean,
        roots: List<DirectoryOverlay>,
    ): Comparator<ResourceDirectoryItem> {
        fun name(item: ResourceDirectoryItem) = item.resource?.name ?: roots.first { it.id == item.overlayId }.name
        val primary =
            when (sort) {
                DirectorySort.Name -> compareBy<ResourceDirectoryItem> { name(it).lowercase() }
                DirectorySort.DateModified ->
                    compareBy<ResourceDirectoryItem> {
                        it.resource?.modifiedAtEpochMillis ?: 0L
                    }
                DirectorySort.DateOpened -> compareBy<ResourceDirectoryItem> { it.resource?.createdAtEpochMillis ?: 0L }
                DirectorySort.Size -> compareBy<ResourceDirectoryItem> { it.resource?.sizeBytes ?: 0L }
                DirectorySort.Type ->
                    compareBy<ResourceDirectoryItem> {
                        name(
                            it,
                        ).substringAfterLast('.', "text/plain").lowercase()
                    }
            }.thenBy { name(it).lowercase() }
        return compareBy<ResourceDirectoryItem> { it.resource?.kind == ResourceKind.FILE }
            .then(if (ascending) primary else primary.reversed())
            .thenBy { it.resource == null }
            .thenBy { it.resource?.remoteId ?: it.overlayId }
    }
}
