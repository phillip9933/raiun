package eu.opencloud.android.next.core.documentsprovider

import android.content.pm.ProviderInfo
import android.os.CancellationSignal
import android.os.OperationCanceledException
import android.os.ParcelFileDescriptor
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File
import java.io.FileNotFoundException
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
class ProviderAccessTest {
    @Test fun cachedReadAccess() {
        val context = RuntimeEnvironment.getApplication()
        val connectivity =
            org.robolectric.Shadows.shadowOf(
                context.getSystemService(android.net.ConnectivityManager::class.java),
            )
        connectivity.setActiveNetworkInfo(null)
        connectivity.clearAllNetworks()
        val database = FileBrowserDatabase.create(context)
        val space =
            SpaceEntity("a", "s", "Space", "project", null, null, "root", "https://cloud.example/dav/s", null, null)
        val directory = resourceCacheDirectory(context.filesDir, "a", "s").apply { mkdirs() }
        val cached = File(directory, "content").apply { writeText("hello") }
        runBlocking(Dispatchers.IO) {
            database.clearAllTables()
            database.accountDao().upsert(AccountEntity("a", "https://cloud.example", "user", "User", "BASIC", false))
            database.spaceDao().insert(space)
            database.resourceDao().insert(
                ResourceEntity(
                    "a",
                    "s",
                    "file",
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
                ),
            )
        }
        val provider = OpenCloudDocumentsProvider()
        provider.attachInfo(
            context,
            ProviderInfo().apply {
                authority = "eu.opencloud.android.next.test.documents"
                exported = true
                grantUriPermissions = true
                readPermission = "android.permission.MANAGE_DOCUMENTS"
                writePermission = "android.permission.MANAGE_DOCUMENTS"
            },
        )
        val id =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                "v1\u0000resource\u0000a\u0000s\u0000file".toByteArray(),
            )
        val rootId = Base64.getUrlEncoder().withoutPadding().encodeToString("v1\u0000account\u0000a".toByteArray())
        assertTrue(provider.isChildDocument(rootId, id))
        runBlocking(Dispatchers.IO) {
            database.resourceDao().insertAll(
                (1..201).map { index ->
                    ResourceEntity(
                        "a",
                        "s",
                        "search-$index",
                        null,
                        "/match-$index",
                        "match-$index",
                        ResourceKind.FILE,
                        "text/plain",
                        0,
                        null,
                        0,
                        0,
                    )
                },
            )
        }
        provider.querySearchDocuments(rootId, "match", null).use { assertEquals(100, it.count) }
        ParcelFileDescriptor.AutoCloseInputStream(provider.openDocument(id, "r", null)).use {
            assertEquals("hello", it.bufferedReader().readText())
        }
        provider.queryDocument(id, null).use {
            it.moveToFirst()
            assertEquals(
                android.provider.DocumentsContract.Document.FLAG_SUPPORTS_WRITE or
                    android.provider.DocumentsContract.Document.FLAG_SUPPORTS_RENAME or
                    android.provider.DocumentsContract.Document.FLAG_SUPPORTS_DELETE,
                it.getInt(it.getColumnIndex(android.provider.DocumentsContract.Document.COLUMN_FLAGS)),
            )
        }
        assertThrows(OperationCanceledException::class.java) {
            provider.openDocument(id, "rw", CancellationSignal().apply { cancel() })
        }
        assertThrows(OperationCanceledException::class.java) {
            provider.openDocument(id, "r", CancellationSignal().apply { cancel() })
        }
        val cancellation = CancellationSignal()
        val editable = provider.openDocument(id, "rw", cancellation)
        cancellation.cancel() // This test must never queue an upload when the editing descriptor closes.
        ParcelFileDescriptor.AutoCloseOutputStream(editable).use { it.write("changed".toByteArray()) }
        assertEquals("hello", cached.readText())
        runBlocking(Dispatchers.IO) { database.spaceDao().upsertAll(listOf(space.copy(isDisabled = true))) }
        assertThrows(FileNotFoundException::class.java) { provider.openDocument(id, "r", null) }
        provider.querySearchDocuments(rootId, "match", null).use { assertEquals(0, it.count) }
    }

    @Test fun `stale excluded rows are hidden from search children metadata and reads`() {
        val context = RuntimeEnvironment.getApplication()
        val database = FileBrowserDatabase.create(context)
        runBlocking(Dispatchers.IO) {
            database.clearAllTables()
            database.accountDao().upsert(AccountEntity("a", "https://cloud.example", "user", "User", "BASIC", false))
            database.spaceDao().insert(
                SpaceEntity(
                    "a",
                    "s",
                    "Space",
                    "project",
                    null,
                    null,
                    "root",
                    "https://cloud.example/dav/s",
                    null,
                    null,
                ),
            )
            database.spaceDao().insert(
                SpaceEntity(
                    "a",
                    "vault",
                    "Vault",
                    "project",
                    null,
                    null,
                    "root",
                    "https://cloud.example/dav/v",
                    null,
                    null,
                ),
            )
            database.vaultExclusionDao().record(
                eu.opencloud.android.next.core.database
                    .VaultExclusion("a", "s", "/private%_"),
            )
            database.vaultExclusionDao().record(
                eu.opencloud.android.next.core.database
                    .VaultExclusion("a", "vault", ""),
            )
            // Deliberately retain metadata after exclusion, including a descendant and a path lookalike.
            listOf("/private%_", "/private%_/child", "/private%_other").forEachIndexed { index, path ->
                database.resourceDao().insert(
                    ResourceEntity(
                        "a",
                        "s",
                        "stale-$index",
                        null,
                        path,
                        "match-$index",
                        ResourceKind.FILE,
                        "text/plain",
                        0,
                        null,
                        0,
                        0,
                    ),
                )
            }
            database.resourceDao().insert(
                ResourceEntity(
                    "a",
                    "vault",
                    "stale",
                    null,
                    "/match",
                    "match-vault",
                    ResourceKind.FILE,
                    "text/plain",
                    0,
                    null,
                    0,
                    0,
                ),
            )
        }
        val provider = OpenCloudDocumentsProvider()
        provider.attachInfo(
            context,
            ProviderInfo().apply {
                authority = "${context.packageName}.documents"
                exported = true
                grantUriPermissions = true
                readPermission = "android.permission.MANAGE_DOCUMENTS"
                writePermission = "android.permission.MANAGE_DOCUMENTS"
            },
        )
        val root = DocumentId.Account("a").encode()
        provider.querySearchDocuments(root, "match", null).use {
            assertEquals(1, it.count)
            assertTrue(it.moveToFirst())
            assertEquals(
                "match-2",
                it.getString(it.getColumnIndex(android.provider.DocumentsContract.Document.COLUMN_DISPLAY_NAME)),
            )
        }
        provider.queryChildDocuments(root, null, sortOrder = null).use {
            assertEquals(2, it.count) // Space and shared collection.
        }
        runBlocking(Dispatchers.IO) {
            assertEquals(1, database.resourceDao().countChildren("a", "s", null))
            assertEquals(listOf("stale-2"), database.resourceDao().childrenPage("a", "s", null, 0).map { it.remoteId })
        }
        listOf(
            DocumentId.Resource("a", "s", "stale-0"),
            DocumentId.Resource("a", "s", "stale-1"),
            DocumentId.Resource("a", "vault", "stale"),
        ).forEach { resource ->
            val id = resource.encode()
            assertThrows(FileNotFoundException::class.java) { provider.queryDocument(id, null) }
            assertThrows(FileNotFoundException::class.java) { provider.queryChildDocuments(id, null, sortOrder = null) }
            assertThrows(FileNotFoundException::class.java) { provider.getDocumentType(id) }
            assertThrows(FileNotFoundException::class.java) { provider.openDocument(id, "r", null) }
            assertThrows(FileNotFoundException::class.java) { provider.isChildDocument(root, id) }
        }
    }

    @Test fun lockedProviderHidesAccountsAndRejectsMetadataAndContent() {
        val context = RuntimeEnvironment.getApplication()
        val lock =
            eu.opencloud.android.next.core.security
                .AppLock(context)
        lock.lock()
        lock.preferences
            .edit()
            .putBoolean("enabled", true)
            .putBoolean("documents", true)
            .commit()
        val provider = OpenCloudDocumentsProvider()
        provider.attachInfo(
            context,
            ProviderInfo().apply {
                authority = "eu.opencloud.android.next.test.documents"
                exported = true
                grantUriPermissions = true
                readPermission = "android.permission.MANAGE_DOCUMENTS"
                writePermission = "android.permission.MANAGE_DOCUMENTS"
            },
        )
        try {
            provider.queryRoots(null).use {
                assertEquals(1, it.count)
                it.moveToFirst()
                assertEquals(
                    "locked",
                    it.getString(it.getColumnIndex(android.provider.DocumentsContract.Root.COLUMN_ROOT_ID)),
                )
            }
            val error = android.app.AuthenticationRequiredException::class.java
            assertThrows(error) { provider.queryDocument("locked", null) }
            assertThrows(error) { provider.queryChildDocuments("locked", null, sortOrder = null) }
            assertThrows(error) { provider.querySearchDocuments("locked", "private", null) }
            assertThrows(error) { provider.getDocumentType("locked") }
            assertThrows(error) { provider.openDocument("locked", "r", null) }
            assertThrows(error) { provider.isChildDocument("locked", "other") }
            lock.authenticated()
            provider.queryDocument("locked", null).use { assertEquals(1, it.count) }
            lock.lock()
            assertThrows(error) { provider.queryChildDocuments("locked", null, sortOrder = null) }
        } finally {
            lock.preferences
                .edit()
                .clear()
                .commit()
            lock.lock()
        }
    }

    @Test fun cachePathIsolation() {
        val context = RuntimeEnvironment.getApplication()
        val first = resourceCacheDirectory(context.filesDir, "a/b", "s")
        val second = resourceCacheDirectory(context.filesDir, "a_b", "s").apply { mkdirs() }
        assertNotEquals(first, second)
        val outside = File(second, "content").apply { writeText("hello") }
        assertNull(validatedCachedFile(first, outside.absolutePath, 5))
        assertNull(validatedCachedFile(second, outside.absolutePath, 4))
        assertEquals(outside.canonicalFile, validatedCachedFile(second, outside.absolutePath, 5))
    }
}
