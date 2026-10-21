package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.network.RemoteTrashResource
import org.junit.Assert.assertEquals
import org.junit.Test

class DeletedFilesBinTest {
    @Test
    fun resourcesForDeletedSpaceKeepsOnlyTheSelectedBin() {
        val personal = RemoteTrashResource("one", "personal", "One", "/one", false, 1)
        val project = RemoteTrashResource("two", "project", "Two", "/two", false, 2)

        assertEquals(listOf(project), resourcesForDeletedSpace(listOf(personal, project), "project"))
    }

    @Test
    fun changingBinsClearsSelectionsFromThePreviousBin() {
        val personal = RemoteTrashResource("one", "personal", "One", "/one", false, 1)
        val project = RemoteTrashResource("two", "project", "Two", "/two", false, 2)

        assertEquals(emptySet<String>(), pruneDeletedSelection(setOf(personal.selectionKey), listOf(project)))
    }
}
