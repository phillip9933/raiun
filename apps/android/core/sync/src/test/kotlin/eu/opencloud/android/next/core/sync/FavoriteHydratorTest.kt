package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.VaultExclusion
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class FavoriteHydratorTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var store: FileBrowserStore
    private val folder =
        ResourceEntity("a", "s", "folder", null, "/Docs", "Docs", ResourceKind.FOLDER, null, 0, null, 0, 0)
    private val file =
        folder.copy(
            remoteId = "favorite",
            parentId = "folder",
            path = "/Docs/A+B",
            name = "A+B",
            kind = ResourceKind.FILE,
        )

    @Before fun setUp() =
        runTest {
            database =
                Room
                    .inMemoryDatabaseBuilder(
                        RuntimeEnvironment.getApplication(),
                        FileBrowserDatabase::class.java,
                    ).build()
            store = FileBrowserStore(database)
            database.accountDao().upsert(AccountEntity("a", "https://cloud.example", "user", "User", "BASIC", false))
        }

    @After fun tearDown() = database.close()

    @Test fun laterRefreshRemovesEarlierUnresolvedFavoriteFromRemainingCount() =
        runTest {
            val exclusionDao = database.vaultExclusionDao()
            val hydrator =
                FavoriteHydrator(
                    store,
                    isVaultExcluded = { account, space, path -> exclusionDao.denies(account, space, path) },
                    currentExclusions = exclusionDao::allForAccount,
                ) { space, parent, _ ->
                    if (space == "s") {
                        val token = store.beginFolderSnapshot("a", space, parent)
                        store.replaceFolderSnapshot("a", space, parent, emptyList(), token)
                    } else {
                        exclusionDao.record(VaultExclusion("a", "s", "/Secret"))
                        val token = store.beginFolderSnapshot("a", space, parent)
                        store.replaceFolderSnapshot(
                            "a",
                            space,
                            parent,
                            listOf(
                                folder.copy(
                                    spaceId = space,
                                    remoteId = "other-folder",
                                    path = "/Other",
                                    name = "Other",
                                ),
                            ),
                            token,
                        )
                    }
                }

            val remaining =
                hydrator.hydrate(
                    "a",
                    mapOf(
                        "s" to mapOf("secret-file" to "/Secret/file"),
                        "t" to mapOf("other-folder" to "/Other"),
                    ),
                )

            assertEquals(0, remaining)
            assertTrue(exclusionDao.denies("a", "s", "/Secret/file"))
        }

    @Test fun vaultDiscoveredDuringFavoriteHydrationIsNotCountedAsOutstanding() =
        runTest {
            val exclusionDao = database.vaultExclusionDao()
            val hydrator =
                FavoriteHydrator(
                    store,
                    isVaultExcluded = { account, space, path -> exclusionDao.denies(account, space, path) },
                    currentExclusions = exclusionDao::allForAccount,
                ) { space, parent, _ ->
                    val token = store.beginFolderSnapshot("a", space, parent)
                    store.replaceDiscoveredFolderSnapshot(
                        "a",
                        space,
                        parent,
                        eu.opencloud.android.next.core.database.FolderSnapshot(
                            resources = emptyList(),
                            excludedVaultPaths = setOf("/Secret"),
                        ),
                        token,
                    )
                }

            val remaining = hydrator.hydrate("a", mapOf("s" to mapOf("secret-file" to "/Secret/file")))

            assertEquals(0, remaining)
            assertTrue(exclusionDao.denies("a", "s", "/Secret/file"))
        }

    @Test fun favoritesAreFilteredByVaultScopeAndLiteralPathBoundary() =
        runTest {
            val locations =
                mapOf(
                    "s" to mapOf("secret" to "/Secret/file", "neighbor" to "/Secretish/file"),
                    "other" to mapOf("other-secret" to "/Secret/file"),
                )
            val visible =
                filterFavoriteLocations(
                    "a",
                    locations,
                    listOf(VaultExclusion("a", "s", "/Secret")),
                )

            assertEquals(mapOf("neighbor" to "/Secretish/file"), visible["s"])
            assertEquals(mapOf("other-secret" to "/Secret/file"), visible["other"])
        }

    @Test fun `child lookup matches exact name parent account and space`() =
        runTest {
            val dao = database.resourceDao()
            val name = "100%_A+B"
            val target = file.copy(name = name)
            dao.insertAll(
                listOf(
                    target,
                    target.copy(accountId = "b"),
                    target.copy(spaceId = "other"),
                    target.copy(remoteId = "root-file", parentId = null),
                    target.copy(remoteId = "case-file", name = name.lowercase()),
                ),
            )
            assertEquals(target, store.child("a", "s", "folder", name))
            assertEquals("root-file", store.child("a", "s", null, name)?.remoteId)
            assertEquals(null, store.child("a", "s", "missing", name))
            assertEquals(null, store.child("a", "s", "folder", "100%"))
        }

    @Test fun `bounded passes discover real parent identities and publish favorite selection`() =
        runTest {
            val requests = mutableListOf<String>()
            val hydrator =
                FavoriteHydrator(store) { space, parent, path ->
                    requests += path
                    val token = store.beginFolderSnapshot("a", space, parent)
                    val listing = if (parent == null) listOf(folder) else listOf(file)
                    store.replaceFolderSnapshot("a", space, parent, listing, token)
                }
            val locations = mapOf("s" to mapOf("favorite" to "/Docs/A+B"))
            val token = store.beginSnapshot("a")
            assertEquals(1, hydrator.hydrate("a", locations, requestBudget = 1))
            assertEquals(listOf("/"), requests)
            assertEquals(null, store.resource("a", "s", "favorite"))
            assertEquals(0, hydrator.hydrate("a", locations, requestBudget = 1))
            assertEquals(listOf("/", "/Docs"), requests)
            assertTrue(store.replaceFavoriteSnapshot("a", mapOf("s" to setOf("favorite")), token))
            val cached = requireNotNull(store.resource("a", "s", "favorite"))
            assertEquals("folder", cached.parentId)
            assertTrue(cached.isFavorite)
            assertEquals(0, hydrator.hydrate("a", locations))
            assertEquals(2, requests.size)
        }

    @Test fun `stale search identity cannot create a fabricated resource`() =
        runTest {
            var requests = 0
            val hydrator =
                FavoriteHydrator(store) { space, parent, _ ->
                    requests++
                    val token = store.beginFolderSnapshot("a", space, parent)
                    val listing = if (parent == null) listOf(folder) else listOf(file)
                    store.replaceFolderSnapshot("a", space, parent, listing, token)
                }
            assertEquals(1, hydrator.hydrate("a", mapOf("s" to mapOf("stale" to "/Docs/A+B"))))
            assertEquals(null, store.resource("a", "s", "stale"))
            assertEquals(2, requests)
        }

    @Test fun `remote rename refreshes existing favorite and preserves pin and cache`() =
        runTest {
            val cached = file.copy(offlinePinned = true, hasLocalCopy = true, localPath = "/cache/file")
            store.replaceFolderSnapshot("a", "s", null, listOf(folder))
            database.resourceDao().insert(cached)
            val renamed = file.copy(name = "Renamed+文.pdf", path = "/Docs/Renamed+文.pdf")
            val requests = mutableListOf<String>()
            val hydrator =
                FavoriteHydrator(store) { space, parent, path ->
                    requests += path
                    val token = store.beginFolderSnapshot("a", space, parent)
                    store.replaceFolderSnapshot("a", space, parent, listOf(renamed), token)
                }
            assertEquals(0, hydrator.hydrate("a", mapOf("s" to mapOf(file.remoteId to renamed.path))))
            val actual = requireNotNull(store.resource("a", "s", file.remoteId))
            assertEquals(renamed.path, actual.path)
            assertTrue(actual.offlinePinned)
            assertEquals("/cache/file", actual.localPath)
            assertEquals(listOf("/Docs"), requests)
        }

    @Test fun `stale search path does not overwrite confirmed file location`() =
        runTest {
            store.replaceFolderSnapshot("a", "s", null, listOf(folder))
            database.resourceDao().insert(file)
            val hydrator =
                FavoriteHydrator(store) { space, parent, _ ->
                    val token = store.beginFolderSnapshot("a", space, parent)
                    store.replaceFolderSnapshot("a", space, parent, listOf(file), token)
                }
            assertEquals(1, hydrator.hydrate("a", mapOf("s" to mapOf(file.remoteId to "/Docs/stale"))))
            assertEquals(file.path, store.resource("a", "s", file.remoteId)?.path)
        }

    @Test fun `stale entries yield to later favorites across new hydrators`() =
        runTest {
            val gone = folder.copy(remoteId = "gone", path = "/Gone", name = "Gone")
            store.replaceFolderSnapshot("a", "s", null, listOf(gone, folder))
            val requests = mutableListOf<String>()

            fun hydrator() =
                FavoriteHydrator(store) { space, parent, path ->
                    requests += path
                    val listing = if (parent == "folder") listOf(file) else emptyList()
                    val token = store.beginFolderSnapshot("a", space, parent)
                    store.replaceFolderSnapshot("a", space, parent, listing, token)
                }
            val entries = mapOf("favorite" to "/Docs/A+B", "a-stale" to "/Gone/missing")
            assertEquals(2, hydrator().hydrate("a", mapOf("s" to entries), requestBudget = 1))
            assertEquals("a-stale", store.favoriteCursor("a")?.resourceId)
            assertEquals(
                1,
                hydrator().hydrate("a", mapOf("s" to entries.toList().reversed().toMap()), requestBudget = 1),
            )
            assertEquals(file.remoteId, store.resource("a", "s", file.remoteId)?.remoteId)
            assertEquals(listOf("/Gone", "/Docs"), requests)
        }

    @Test fun `item budget bounds cached entries as well as requests`() =
        runTest {
            store.replaceFolderSnapshot("a", "s", null, listOf(folder))
            store.replaceFolderSnapshot("a", "s", "folder", listOf(file))
            val locations = mapOf("s" to mapOf("folder" to "/Docs", "favorite" to "/Docs/A+B"))
            val hydrator = FavoriteHydrator(store) { _, _, _ -> error("Cached entries need no requests") }
            assertEquals(1, hydrator.hydrate("a", locations, itemBudget = 1))
            assertEquals("favorite", store.favoriteCursor("a")?.resourceId)
            assertEquals(1, hydrator.hydrate("a", locations, itemBudget = 1))
            assertEquals("folder", store.favoriteCursor("a")?.resourceId)
        }

    @Test fun `failed or cancelled discovery does not create a favorite`() =
        runTest {
            val hydrator = FavoriteHydrator(store) { _, _, _ -> throw CancellationException("cancelled") }
            try {
                hydrator.hydrate("a", mapOf("s" to mapOf("favorite" to "/Docs/A+B")))
                org.junit.Assert.fail("Cancellation must escape")
            } catch (_: CancellationException) {
                assertEquals(null, store.resource("a", "s", "favorite"))
                assertTrue(store.children("a", "s", null).isEmpty())
            }
        }
}
