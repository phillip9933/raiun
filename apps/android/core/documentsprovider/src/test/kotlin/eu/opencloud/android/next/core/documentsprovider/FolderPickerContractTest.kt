package eu.opencloud.android.next.core.documentsprovider

import android.content.pm.ProviderInfo
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
class FolderPickerContractTest {
    @Test fun `picker discovers tree roots but grants only concrete folders`() {
        val context = RuntimeEnvironment.getApplication()
        val database = FileBrowserDatabase.create(context)
        runBlocking(Dispatchers.IO) {
            database.clearAllTables()
            database.accountDao().upsert(AccountEntity("a", "https://example.test", "u", "User", "BASIC", false))
            database.spaceDao().insert(
                SpaceEntity("a", "s", "Space", "personal", null, null, "root", "https://example.test/dav", null, null),
            )
            val template =
                SpaceEntity(
                    "a",
                    "project",
                    "Team",
                    "project",
                    null,
                    null,
                    "team-root",
                    "https://example.test/team",
                    null,
                    null,
                )
            database.spaceDao().upsertAll(
                listOf(
                    template,
                    template.copy(driveId = "named-shares", name = "Shares"),
                    template.copy(driveId = "virtual", name = "Shares", type = "virtual"),
                    template.copy(driveId = "mount", name = "Incoming", type = "mountpoint"),
                    template.copy(driveId = "share", name = "Shared item", type = "share"),
                    template.copy(driveId = "disabled", name = "Disabled", isDisabled = true),
                    template.copy(driveId = "deleted", name = "Deleted", isDeleted = true),
                ),
            )
            database.resourceDao().insertAll(
                listOf(
                    ResourceEntity(
                        "a",
                        "s",
                        "folder",
                        null,
                        "/Backup",
                        "Backup",
                        ResourceKind.FOLDER,
                        null,
                        0,
                        "\"v1\"",
                        0,
                        0,
                    ),
                    ResourceEntity(
                        "a",
                        "s",
                        "child",
                        "folder",
                        "/Backup/file",
                        "file",
                        ResourceKind.FILE,
                        null,
                        0,
                        "\"v1\"",
                        0,
                        0,
                    ),
                    ResourceEntity(
                        "a",
                        "s",
                        "sibling",
                        null,
                        "/Other",
                        "Other",
                        ResourceKind.FILE,
                        null,
                        0,
                        "\"v1\"",
                        0,
                        0,
                    ),
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
        provider.queryRoots(null).use {
            assertTrue(it.moveToFirst())
            val flags = it.getInt(it.getColumnIndexOrThrow(Root.COLUMN_FLAGS))
            assertTrue(flags and Root.FLAG_SUPPORTS_IS_CHILD != 0)
            assertTrue(flags and Root.FLAG_SUPPORTS_CREATE != 0)
        }
        provider.queryChildDocuments(id("account", "a"), null, sortOrder = null).use { cursor ->
            val names = mutableListOf<String>()
            val ids = mutableListOf<String>()
            while (cursor.moveToNext()) {
                names += cursor.getString(cursor.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME))
                ids += cursor.getString(cursor.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID))
            }
            assertEquals(listOf("Personal files", "Shared with me", "Shares", "Team"), names.sorted())
            assertTrue(id("space", "a", "named-shares") in ids)
            assertFalse(id("space", "a", "virtual") in ids)
        }

        fun flags(id: String): Int =
            provider.queryDocument(id, arrayOf(Document.COLUMN_FLAGS)).use {
                it.moveToFirst()
                it.getInt(0)
            }
        assertTrue(flags(id("account", "a")) and Document.FLAG_DIR_BLOCKS_OPEN_DOCUMENT_TREE != 0)
        assertEquals(Document.FLAG_DIR_SUPPORTS_CREATE, flags(id("space", "a", "s")))
        assertEquals(Document.FLAG_DIR_SUPPORTS_CREATE, flags(id("resource", "a", "s", "folder")))
        val fileFlags = flags(id("resource", "a", "s", "child"))
        assertTrue(fileFlags and Document.FLAG_SUPPORTS_WRITE != 0)
        assertTrue(fileFlags and Document.FLAG_SUPPORTS_RENAME != 0)
        assertTrue(fileFlags and Document.FLAG_SUPPORTS_DELETE != 0)
        assertTrue(provider.isChildDocument(id("resource", "a", "s", "folder"), id("resource", "a", "s", "child")))
        assertFalse(provider.isChildDocument(id("resource", "a", "s", "folder"), id("resource", "a", "s", "sibling")))
    }

    private fun id(vararg parts: String) =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            (listOf("v1") + parts).joinToString("\u0000").toByteArray(),
        )
}
