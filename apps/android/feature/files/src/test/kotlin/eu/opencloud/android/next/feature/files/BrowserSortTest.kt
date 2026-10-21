package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import org.junit.Assert.assertEquals
import org.junit.Test

class BrowserSortTest {
    @Test fun `folders stay first in both name directions`() {
        val items = listOf(item("a.txt"), item("Z folder", true), item("b.txt"), item("A folder", true))
        assertEquals(
            listOf("A folder", "Z folder", "a.txt", "b.txt"),
            items.sortedWith(BrowserSortCriterion.Name.comparator(true)).map { it.name },
        )
        assertEquals(
            listOf("Z folder", "A folder", "b.txt", "a.txt"),
            items.sortedWith(BrowserSortCriterion.Name.comparator(false)).map { it.name },
        )
    }

    @Test fun `file type sorts extensions case insensitively with name tie breaker`() {
        val items = listOf(item("b.JPG"), item("a.txt"), item("a.jpg"), item("folder", true))
        assertEquals(
            listOf("folder", "a.jpg", "b.JPG", "a.txt"),
            items.sortedWith(BrowserSortCriterion.Type.comparator(true)).map { it.name },
        )
    }

    private fun item(
        name: String,
        folder: Boolean = false,
    ) = ResourceEntity(
        "account",
        "space",
        name,
        null,
        "/$name",
        name,
        if (folder) ResourceKind.FOLDER else ResourceKind.FILE,
        null,
        0,
        null,
        0,
        0,
    )
}
