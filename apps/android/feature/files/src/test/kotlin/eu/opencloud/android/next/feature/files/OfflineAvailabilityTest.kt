package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class OfflineAvailabilityTest {
    private val file =
        ResourceEntity(
            "a",
            "s",
            "file",
            null,
            "/folder/file",
            "file",
            ResourceKind.FILE,
            null,
            4,
            null,
            0,
            0,
            hasLocalCopy = true,
            localPath = "/cache/file",
        )
    private val folder =
        file.copy(
            remoteId = "folder",
            path = "/folder",
            kind = ResourceKind.FOLDER,
            offlinePinned = true,
        )

    @Test fun filterRespectsPinsInheritedFromFolders() {
        assertTrue(OfflineFilter.ALL.matches(file, listOf(folder)))
        assertTrue(OfflineFilter.PINNED.matches(file, listOf(folder)))
        assertFalse(OfflineFilter.TEMPORARY.matches(file, listOf(folder)))
        assertTrue(OfflineFilter.TEMPORARY.matches(file, emptyList()))
    }

    @Test fun hiddenExtensionsDoNotChangeFolderOrDotfileNames() {
        val options =
            eu.opencloud.android.next.core.datastore
                .FileDisplayOptions(showExtensions = false)
        org.junit.Assert.assertEquals("photo", displayFileName(file.copy(name = "photo.jpg"), options))
        org.junit.Assert.assertEquals(".nomedia", displayFileName(file.copy(name = ".nomedia"), options))
        org.junit.Assert.assertEquals("folder.name", displayFileName(folder.copy(name = "folder.name"), options))
        org.junit.Assert.assertNull(formattedModified(0))
    }

    @Test fun recentChangesShowTimeAndOlderChangesShowDate() {
        val now = 1_800_000_000_000L
        val recent = now - 60_000
        val old = now - 86_400_000
        org.junit.Assert.assertEquals(
            java.text.DateFormat
                .getTimeInstance(java.text.DateFormat.SHORT)
                .format(java.util.Date(recent)),
            formattedModified(recent, now),
        )
        org.junit.Assert.assertEquals(
            java.text.DateFormat
                .getDateInstance(java.text.DateFormat.SHORT)
                .format(java.util.Date(old)),
            formattedModified(old, now),
        )
    }

    @Test fun cachedAndExplicitlyOfflineFilesAreDistinct() {
        assertFalse(isKeptOffline(file, emptyList()))
        assertTrue(isKeptOffline(file.copy(offlinePinned = true), emptyList()))
    }

    @Test fun pinnedFolderIncludesOnlyItsOwnDescendants() {
        assertTrue(isKeptOffline(file, listOf(folder)))
        assertFalse(isKeptOffline(file.copy(path = "/folder-other/file"), listOf(folder)))
        assertFalse(isKeptOffline(file.copy(accountId = "other"), listOf(folder)))
        assertFalse(isKeptOffline(file.copy(spaceId = "other"), listOf(folder)))
    }
}
