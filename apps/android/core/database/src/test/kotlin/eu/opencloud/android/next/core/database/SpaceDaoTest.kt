package eu.opencloud.android.next.core.database

import androidx.room.Room
import kotlinx.coroutines.test.runTest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class SpaceDaoTest {
    private lateinit var database: FileBrowserDatabase
    private lateinit var dao: SpaceDao

    @Before
    fun setUp() {
        database =
            Room
                .inMemoryDatabaseBuilder(RuntimeEnvironment.getApplication(), FileBrowserDatabase::class.java)
                .allowMainThreadQueries()
                .build()
        dao = database.spaceDao()
    }

    @After
    fun tearDown() = database.close()

    @Test
    fun `unimplemented remote mutations never change cached resources or spaces`() =
        runTest {
            val store = FileBrowserStore(database)
            val originalSpace = space("account", "project", "Project")
            dao.upsertAll(listOf(originalSpace))
            val original =
                ResourceEntity(
                    "account",
                    "project",
                    "file",
                    null,
                    "/before",
                    "before",
                    eu.opencloud.android.next.core.model.ResourceKind.FILE,
                    null,
                    5,
                    null,
                    0,
                    0,
                )
            store.replaceFolderSnapshot("account", "project", null, listOf(original))
            val actions: List<suspend () -> Unit> =
                listOf(
                    { store.rename("account", "project", "file", "after") },
                    { store.move("account", "project", "file", null) },
                    { store.copy("account", "project", "file", null) },
                    { store.createSpace("account", "Invented") },
                )
            actions.forEach { action ->
                try {
                    action()
                    org.junit.Assert.fail("A server operation must confirm this mutation")
                } catch (_: IllegalStateException) {
                    assertEquals(original, store.resource("account", "project", "file"))
                    assertEquals(listOf(original), store.children("account", "project", null))
                    assertEquals(listOf(originalSpace), store.spaces("account"))
                }
            }
        }

    @Test
    fun `spaces are stored per account with graph metadata`() =
        runTest {
            dao.upsertAll(
                listOf(
                    space("account", "project", "Project").copy(
                        driveAlias = "project-mars",
                        webUrl = "https://cloud.example.test/f/project",
                        ownerId = "alice",
                        ownerName = "Alice",
                        quotaBytes = 100,
                        quotaUsedBytes = 40,
                        quotaRemainingBytes = 60,
                        quotaState = "normal",
                    ),
                    space("other", "other", "Other"),
                ),
            )

            val stored = dao.findSpaces("account").single()
            assertEquals("project-mars", stored.driveAlias)
            assertEquals("Alice", stored.ownerName)
            assertEquals(40L, stored.quotaUsedBytes)
            assertEquals(60L, stored.quotaRemainingBytes)
        }

    @Test
    fun `deleted spaces are excluded and can be removed`() =
        runTest {
            val active = space("account", "active", "Active")
            val deleted = space("account", "deleted", "Deleted").copy(isDeleted = true)
            dao.upsertAll(listOf(active, deleted))

            assertEquals(listOf(active), dao.findSpaces("account"))
            dao.delete(active)
            assertNull(dao.findById("account", "active"))
        }

    private fun space(
        accountId: String,
        driveId: String,
        name: String,
    ) = SpaceEntity(
        accountId = accountId,
        driveId = driveId,
        name = name,
        type = "project",
        description = null,
        ownerName = null,
        rootId = "$driveId-root",
        rootWebDavUrl = "https://cloud.example.test/dav/spaces/$driveId",
        rootETag = null,
        quotaBytes = null,
    )
}
