package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class DirectorySelectionTest {
    @Test fun `explicit selections survive page changes without retaining unselected rows`() {
        val first = resource("first")
        val ignored = resource("ignored")
        val original =
            FileBrowserUiState(resources = listOf(first, ignored), selectedIds = setOf(first.selectionKey))
                .withRetainedSelection(emptyList())
        assertEquals(listOf(first), original.selectedResources)
        val second = resource("second")
        val next =
            original
                .copy(resources = listOf(second), selectedIds = original.selectedIds + second.selectionKey)
                .withRetainedSelection(original.selectedResources)
        assertEquals(setOf(first, second), next.selectedResources.toSet())
        val deselected =
            next
                .copy(
                    selectedIds = setOf(second.selectionKey),
                ).withRetainedSelection(next.selectedResources)
        assertEquals(listOf(second), deselected.selectedResources)
        assertTrue(
            next
                .copy(
                    selectedIds = emptySet(),
                ).withRetainedSelection(next.selectedResources)
                .selectedResources
                .isEmpty(),
        )
    }

    @Test fun `a current row refreshes the selected snapshot before a later action`() {
        val old = resource("selected")
        val fresh = old.copy(eTag = "new-version", hasLocalCopy = true)
        val next =
            FileBrowserUiState(resources = listOf(fresh), selectedIds = setOf(old.selectionKey))
                .withRetainedSelection(listOf(old))
        assertEquals(listOf(fresh), next.selectedResources)
    }

    private fun resource(id: String) =
        ResourceEntity(
            "account",
            "space",
            id,
            null,
            id,
            id,
            ResourceKind.FILE,
            "text/plain",
            1,
            "tag",
            1,
            1,
        )
}
