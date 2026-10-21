package eu.opencloud.android.next.core.documentsprovider

import eu.opencloud.android.next.core.database.SharedFolderEntry
import eu.opencloud.android.next.core.database.SharedFolderScopeEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.FileNotFoundException

class SharedDocumentIdTest {
    private val id = SharedDocumentId("account", "share", "scope", "file")
    private val binding = SharedFolderScopeEntity("account", "scope", "share", "server-drive", "root", "https://a/dav/")
    private val entry = SharedFolderEntry("account", "scope", "file", "/", "/f", "f", false, null, 5, "v1", 1, 1)

    @Test fun roundTripKeepsShareAndScopeSeparateFromDrive() {
        assertEquals(id, SharedDocumentId.decode(id.encode()))
        val unicode = id.copy(remote = "資料 📷")
        assertEquals(unicode, SharedDocumentId.decode(unicode.encode()))
        assertNotEquals(id.encode(), id.copy(share = "another").encode())
        assertNotEquals(id.encode(), id.copy(scope = "another-root").encode())
        assertEquals("scope", id.request(binding, entry).scopeId)
    }

    @Test fun rejectsMalformedNoncanonicalAndOversizedIds() {
        for (encoded in listOf("v1", "shared-v1:!", id.encode() + "=", "shared-v1:" + "a".repeat(4096))) {
            assertThrows(FileNotFoundException::class.java) { SharedDocumentId.decode(encoded) }
        }
        assertThrows(IllegalArgumentException::class.java) { id.copy(account = "").encode() }
        assertThrows(IllegalArgumentException::class.java) { id.copy(remote = "a\u0000b").encode() }
    }

    @Test fun rejectsCrossAccountShareScopeAndFolderSelection() {
        val bindings =
            listOf(binding.copy(accountId = "other"), binding.copy(shareId = "other"), binding.copy(scopeId = "other"))
        for (other in bindings) {
            assertThrows(FileNotFoundException::class.java) { id.request(other, entry) }
        }
        val entries =
            listOf(
                entry.copy(accountId = "other"),
                entry.copy(scopeId = "other"),
                entry.copy(remoteId = "other"),
                entry.copy(isFolder = true),
            )
        for (other in entries) {
            assertThrows(FileNotFoundException::class.java) { id.request(binding, other) }
        }
    }
}
