package eu.opencloud.android.next.core.documentsprovider

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class DocumentWriteAccessTest {
    private val context = RuntimeEnvironment.getApplication()
    private val database = Room.inMemoryDatabaseBuilder(context, FileBrowserDatabase::class.java).build()
    private val access = DocumentWriteAccess(context, FileBrowserStore(database))
    private val account = AccountEntity("account", "https://example.test", "user", "User", "BASIC", false)
    private val space =
        SpaceEntity(
            "account",
            "space",
            "Space",
            "project",
            null,
            null,
            "root",
            "https://example.test/dav",
            null,
            null,
        )
    private val cached =
        File(resourceCacheDirectory(context.filesDir, "account", "space"), "content")
            .apply {
                parentFile!!.mkdirs()
                writeText("hello")
            }
    private val resource =
        ResourceEntity(
            "account",
            "space",
            "resource",
            null,
            "/file",
            "file",
            ResourceKind.FILE,
            "text/plain",
            5,
            "\"v1\"",
            0,
            0,
            hasLocalCopy = true,
            localPath = cached.absolutePath,
        )

    @Before fun seed() =
        runBlocking {
            database.accountDao().upsert(account)
            database.spaceDao().insert(space)
            database.resourceDao().insert(resource)
        }

    @After fun close() {
        database.close()
    }

    @Test fun `cloud-only preparation downloads the captured version and cached opens skip downloading`() =
        runBlocking {
            val cloud = resource.copy(hasLocalCopy = false, localPath = null)
            database.resourceDao().update(cloud)
            assertTrue(access.editable(cloud))
            var downloads = 0
            val original =
                access.prepare(cloud, { true }) {
                    assertEquals(cloud, it)
                    downloads++
                    database.resourceDao().update(resource)
                }
            assertEquals("hello", original.readText())
            access.prepare(resource, { true }) { downloads++ }
            assertEquals(1, downloads)
        }

    @Test fun `changed version and revoked access during preparation never yield an editable source`() =
        runBlocking<Unit> {
            val cloud = resource.copy(hasLocalCopy = false, localPath = null)
            database.resourceDao().update(cloud)
            assertThrows(IllegalStateException::class.java) {
                runBlocking {
                    access.prepare(cloud, { true }) { database.resourceDao().update(resource.copy(eTag = "\"v2\"")) }
                }
            }
            database.resourceDao().update(cloud)
            var allowed = true
            assertThrows(IllegalStateException::class.java) {
                runBlocking {
                    access.prepare(cloud, { allowed }) {
                        database.resourceDao().update(resource)
                        allowed = false
                    }
                }
            }
        }

    @Test fun `cancelled or incomplete preparation never returns an editable source`() =
        runBlocking<Unit> {
            val cloud = resource.copy(hasLocalCopy = false, localPath = null)
            database.resourceDao().update(cloud)
            assertThrows(CancellationException::class.java) {
                runBlocking { access.prepare(cloud, { true }) { throw CancellationException("cancelled") } }
            }
            assertThrows(java.io.FileNotFoundException::class.java) {
                runBlocking { access.prepare(cloud, { true }) {} }
            }
        }

    @Test fun `editing requires an isolated complete cache and strong version`() {
        assertEquals(cached.canonicalFile, access.original(resource))
        assertNull(access.original(resource.copy(eTag = "W/\"v1\"")))
        assertNull(access.original(resource.copy(hasLocalCopy = false)))
        assertNull(access.original(resource.copy(sizeBytes = 6)))
        assertNull(access.original(resource.copy(kind = ResourceKind.FOLDER)))
        val outside = File(context.cacheDir, "outside").apply { writeText("hello") }
        assertNull(access.original(resource.copy(localPath = outside.absolutePath)))
    }

    @Test fun `lock revocation account deactivation and disabled spaces deny writeback`() =
        runBlocking {
            assertTrue(access.authorized(resource) { true })
            assertFalse(access.authorized(resource) { false })
            database.accountDao().upsert(account.copy(isActive = false))
            assertFalse(access.authorized(resource) { true })
            database.accountDao().upsert(account)
            database.spaceDao().upsertAll(listOf(space.copy(isDisabled = true)))
            assertFalse(access.authorized(resource) { true })
            database.spaceDao().upsertAll(listOf(space.copy(isDeleted = true)))
            assertFalse(access.authorized(resource) { true })
        }

    @Test fun `changed source version or path cannot authorize an old edit`() =
        runBlocking {
            database.resourceDao().update(resource.copy(eTag = "\"v2\""))
            assertFalse(access.authorized(resource) { true })
            database.resourceDao().update(resource.copy(path = "/renamed"))
            assertFalse(access.authorized(resource) { true })
            database.resourceDao().delete(resource)
            assertFalse(access.authorized(resource) { true })
        }
}
