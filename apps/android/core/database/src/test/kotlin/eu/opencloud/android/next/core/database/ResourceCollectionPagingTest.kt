package eu.opencloud.android.next.core.database

import androidx.room.Room
import androidx.room.withTransaction
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
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
class ResourceCollectionPagingTest {
    private val database =
        Room
            .inMemoryDatabaseBuilder(
                RuntimeEnvironment.getApplication(),
                FileBrowserDatabase::class.java,
            ).build()
    private val paging = ResourceCollectionPaging(database)
    private val account = AccountEntity("account", "https://example.test", "user", "User", "BASIC", false)
    private val space = SpaceEntity("account", "space", "Personal", "personal", null, null, "root", null, null, null)

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(account)
            database.spaceDao().upsertAll(listOf(space, space.copy(driveId = "space2")))
        }

    @After fun close() = database.close()

    @Test fun `inventories traverse stable windows for all sorts and cross-space ties`() =
        runBlocking {
            val rows =
                (0 until 1001).map { n ->
                    resource(n.toString().padStart(4, '0'), "same.${if (n % 2 == 0) "txt" else "pdf"}")
                        .copy(
                            spaceId = if (n % 3 == 0) "space2" else "space",
                            sizeBytes = (n % 5).toLong(),
                            createdAtEpochMillis = (n % 7).toLong(),
                            modifiedAtEpochMillis = (n % 11).toLong(),
                            kind = if (n % 13 == 0) ResourceKind.FOLDER else ResourceKind.FILE,
                        )
                }
            database.withTransaction { database.resourceDao().insertAll(rows) }
            for (collection in ResourceCollection.entries) {
                for (sort in DirectorySort.entries) {
                    for (ascending in listOf(true, false)) {
                        val actual = mutableListOf<ResourceEntity>()
                        var offset = 0
                        do {
                            val page =
                                paging
                                    .load(
                                        "account",
                                        collection,
                                        ResourceCollectionOptions(offset = offset, sort = sort, ascending = ascending),
                                    ).page
                            assertEquals(1001, page.total)
                            assertTrue(page.entries.size in 1..128)
                            actual += page.entries.mapNotNull { it.resource }
                            offset += 128
                        } while (page.hasNext)
                        val primary =
                            when (sort) {
                                DirectorySort.Name -> compareBy<ResourceEntity> { it.name }
                                DirectorySort.DateModified -> compareBy { it.modifiedAtEpochMillis }
                                DirectorySort.DateOpened -> compareBy { it.createdAtEpochMillis }
                                DirectorySort.Size -> compareBy { it.sizeBytes }
                                DirectorySort.Type -> compareBy { it.name.substringAfterLast('.') }
                            }.thenBy { it.name }
                        val expected =
                            rows.sortedWith(
                                compareBy<ResourceEntity> { it.kind != ResourceKind.FOLDER }
                                    .then(if (ascending) primary else primary.reversed())
                                    .thenBy { it.spaceId }
                                    .thenBy { it.remoteId },
                            )
                        assertEquals("$collection $sort $ascending", expected, actual)
                        assertEquals(1001, actual.map { it.spaceId to it.remoteId }.toSet().size)
                    }
                }
            }
        }

    @Test fun `Unicode search visibility and vault exclusions precede paging`() =
        runBlocking {
            database.resourceDao().insertAll(
                (0 until 400).map {
                    resource("id$it", if (it % 2 == 0) "Ä_% document$it" else "unrelated$it")
                } +
                    listOf(
                        resource("hidden", ".Ä_%"),
                        resource("vault", "Ä_% root").copy(path = "/%_vault"),
                        resource("child", "Ä_% child").copy(path = "/%_vault/child"),
                        resource("sibling", "Ä_% sibling").copy(path = "/%xvault/child"),
                        resource("remembered", "Ä_% remembered").copy(path = "/remembered"),
                    ),
            )
            database.vaultExclusionDao().record(VaultExclusion("account", "space", "/%_vault"))
            val options =
                ResourceCollectionOptions(
                    offset = 128,
                    query = "ä_%",
                    roots = listOf(ResourceCollectionRoot("space", "remembered", "/remembered")),
                )
            for (collection in ResourceCollection.entries) {
                val page = paging.load("account", collection, options).page
                assertEquals(201, page.total)
                assertEquals(73, page.entries.size)
                assertTrue(page.entries.all { it.resource!!.name.contains("ä_%", true) })
                assertEquals(202, paging.load("account", collection, options.copy(showHidden = true)).page.total)
            }
            // Matching TEMP keys and remembered roots must not leak to the next independent snapshot.
            assertEquals(
                402,
                paging.load("account", ResourceCollection.Favorites, ResourceCollectionOptions()).page.total,
            )
        }

    @Test fun `pin filtering respects literal ancestry and account boundaries`() =
        runBlocking {
            val pin =
                resource(
                    "pin",
                    "Pinned",
                ).copy(
                    path = "/%_folder",
                    kind = ResourceKind.FOLDER,
                    offlinePinned = true,
                    hasLocalCopy = false,
                    localPath = null,
                )
            val children = (0 until 270).map { resource("child$it", "child$it").copy(path = "/%_folder/file$it") }
            val temporary = resource("temp", "Temporary").copy(path = "/%xfolder/file")
            database.resourceDao().insertAll(
                children + listOf(pin, temporary, resource("other", "Other").copy(accountId = "other")),
            )
            val options = ResourceCollectionOptions(offset = 256, offlineFilter = ResourceOfflineFilter.Pinned)
            val page = paging.load("account", ResourceCollection.Offline, options)
            assertEquals(270, page.page.total)
            assertEquals(14, page.keptOffline.size)
            assertEquals(
                setOf("temp"),
                paging
                    .load(
                        "account",
                        ResourceCollection.Offline,
                        options.copy(offlineFilter = ResourceOfflineFilter.Temporary),
                    ).page.entries
                    .mapNotNull { it.resource?.remoteId }
                    .toSet(),
            )
            assertEquals(listOf(children.first()), paging.keptOffline(listOf(children.first(), temporary)))
            database.resourceDao().setOfflinePinned("account", "space", "pin", false)
            assertEquals(0, paging.load("account", ResourceCollection.Offline, options).page.total)
            assertEquals(
                271,
                paging
                    .load(
                        "account",
                        ResourceCollection.Offline,
                        options.copy(offlineFilter = ResourceOfflineFilter.Temporary),
                    ).page.total,
            )
        }

    @Test fun `metadata and access changes yield fresh clamped snapshots`() =
        runBlocking {
            val rows = (0 until 270).map { resource("$it", "file${it.toString().padStart(3, '0')}") }
            database.resourceDao().insertAll(rows)
            val events = Channel<Int>(Channel.UNLIMITED)
            val job = launch { paging.invalidations("account").collect { events.send(it) } }

            suspend fun next() = withTimeout(10_000) { events.receive() }
            try {
                assertEquals(270, next())
                database.resourceDao().upsert(rows.last().copy(name = "AAA"))
                assertEquals(270, next())
                assertEquals(
                    "269",
                    paging
                        .load(
                            "account",
                            ResourceCollection.Favorites,
                            ResourceCollectionOptions(),
                        ).page.entries
                        .first()
                        .resource
                        ?.remoteId,
                )
                database.withTransaction { rows.drop(9).forEach { database.resourceDao().delete(it) } }
                next()
                val clamped =
                    paging
                        .load(
                            "account",
                            ResourceCollection.Favorites,
                            ResourceCollectionOptions(offset = 256),
                        ).page
                assertEquals(0, clamped.offset)
                assertEquals(9, clamped.total)
                assertFalse(clamped.hasNext)
                database.spaceDao().upsertAll(listOf(space.copy(isDisabled = true)))
                next()
                assertEquals(
                    0,
                    paging.load("account", ResourceCollection.Offline, ResourceCollectionOptions()).page.total,
                )
                database.accountDao().upsert(account.copy(isActive = false))
                next()
                assertFalse(
                    paging.load("account", ResourceCollection.Favorites, ResourceCollectionOptions()).page.accessible,
                )
                assertEquals(
                    0,
                    paging.load("other", ResourceCollection.Offline, ResourceCollectionOptions()).page.total,
                )
            } finally {
                job.cancel()
            }
        }

    @Test fun `byte aggregation validates aliases across batches and cleans cancellation`() =
        runBlocking {
            database.resourceDao().insertAll((0 until 301).map { resource(it.toString().padStart(4, '0'), "file$it") })
            val visited = mutableListOf<String>()
            val bytes =
                paging.offlineBytes("account") { row ->
                    visited += row.remoteId
                    // First alias fails validation; later aliases can still establish this canonical file.
                    when (row.remoteId) {
                        "0000" -> null
                        "0001", "0129", "0300" -> "/canonical/shared" to 42L
                        else -> "/canonical/${row.remoteId}" to 1L
                    }
                }
            assertEquals(301, visited.size)
            assertEquals(339L, bytes)
            try {
                paging.offlineBytes("account") { throw CancellationException("synthetic cancellation") }
                throw AssertionError("Cancellation swallowed")
            } catch (_: CancellationException) {
            }
            assertEquals(301L, paging.offlineBytes("account") { it.remoteId to 1L })
        }

    private fun resource(
        id: String,
        name: String,
    ) = ResourceEntity(
        "account",
        "space",
        id,
        null,
        "/$name",
        name,
        ResourceKind.FILE,
        "text/plain",
        1,
        "tag",
        1,
        1,
        isFavorite = true,
        hasLocalCopy = true,
        localPath = "/synthetic/$id",
    )
}
