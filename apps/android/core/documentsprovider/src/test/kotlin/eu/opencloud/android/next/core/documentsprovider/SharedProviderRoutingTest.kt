package eu.opencloud.android.next.core.documentsprovider

import android.content.pm.ProviderInfo
import android.os.CancellationSignal
import android.os.OperationCanceledException
import android.provider.DocumentsContract.Document
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.FileNotFoundException
import java.util.Base64

@RunWith(RobolectricTestRunner::class)
class SharedProviderRoutingTest {
    private fun provider() =
        OpenCloudDocumentsProvider().apply {
            attachInfo(
                RuntimeEnvironment.getApplication(),
                ProviderInfo().apply {
                    authority = "test.shared.routing"
                    exported = true
                    grantUriPermissions = true
                    readPermission = "android.permission.MANAGE_DOCUMENTS"
                    writePermission = "android.permission.MANAGE_DOCUMENTS"
                },
            )
        }

    @Test fun rejectsUnavailableSharedIdsAndWriteModesWithoutOrdinarySpaceFallback() {
        val provider = provider()
        val id = SharedDocumentId("missing-account", "share", "scope", "file").encode()
        assertThrows(FileNotFoundException::class.java) { provider.queryDocument(id, null) }
        assertThrows(FileNotFoundException::class.java) { provider.getDocumentType(id) }
        assertThrows(FileNotFoundException::class.java) { provider.openDocument(id, "r", null) }
        assertThrows(FileNotFoundException::class.java) { provider.openDocument(id, "rw", null) }
        assertFalse(provider.isChildDocument("locked", id))
        assertFalse(provider.isChildDocument(id, id))
    }

    @Test fun cancelledSharedOpenStopsBeforeResolvingAccount() {
        val provider = provider()
        val id = SharedDocumentId("missing-account", "share", "scope", "file").encode()
        val signal = CancellationSignal().apply { cancel() }
        assertThrows(OperationCanceledException::class.java) { provider.openDocument(id, "r", signal) }
    }

    @Test fun sharedCollectionIsVisibleButCannotBecomeABroadTreeGrant() {
        val database = FileBrowserDatabase.create(RuntimeEnvironment.getApplication())
        runBlocking(Dispatchers.IO) {
            database.clearAllTables()
            database.accountDao().upsert(
                AccountEntity("picker", "https://cloud.example", "user", "User", "BASIC", false),
            )
        }
        val provider = provider()
        val accountId =
            Base64.getUrlEncoder().withoutPadding().encodeToString(
                "v1\u0000account\u0000picker".toByteArray(),
            )
        val collection = SharedCollectionId("picker").encode()
        provider.queryChildDocuments(accountId, null, sortOrder = null).use {
            assertEquals(1, it.count)
            assertTrue(it.moveToFirst())
            assertEquals(collection, it.getString(it.getColumnIndexOrThrow(Document.COLUMN_DOCUMENT_ID)))
            assertEquals("Shared with me", it.getString(it.getColumnIndexOrThrow(Document.COLUMN_DISPLAY_NAME)))
            assertEquals(
                Document.FLAG_DIR_BLOCKS_OPEN_DOCUMENT_TREE,
                it.getInt(it.getColumnIndexOrThrow(Document.COLUMN_FLAGS)),
            )
        }
        provider.queryDocument(collection, arrayOf(Document.COLUMN_DISPLAY_NAME, "unknown")).use {
            assertTrue(it.moveToFirst())
            assertEquals("Shared with me", it.getString(0))
            assertTrue(it.isNull(1))
        }
        assertEquals(Document.MIME_TYPE_DIR, provider.getDocumentType(collection))
        assertFalse(provider.isChildDocument(accountId, collection))
        assertFalse(provider.isChildDocument(collection, SharedDocumentId("picker", "share", "scope", "file").encode()))
        assertThrows(FileNotFoundException::class.java) { provider.openDocument(collection, "r", null) }
        runBlocking(Dispatchers.IO) { database.clearAllTables() }
        assertThrows(FileNotFoundException::class.java) { provider.queryDocument(collection, null) }
        assertThrows(
            FileNotFoundException::class.java,
        ) { provider.queryChildDocuments(collection, null, sortOrder = null) }
    }

    @Test fun collectionIdsRejectMalformedAndNoncanonicalValues() {
        val encoded = SharedCollectionId("account/日本語").encode()
        assertEquals("account/日本語", SharedCollectionId.decode(encoded).account)
        for (invalid in listOf("shared-collection-v1:", encoded + "=", "shared-collection-v1:%%%")) {
            assertThrows(FileNotFoundException::class.java) { SharedCollectionId.decode(invalid) }
        }
    }
}
