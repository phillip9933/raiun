package eu.opencloud.android.next.core.datastore

import org.junit.Assert.assertEquals
import org.junit.Test

class NavigationItemsTest {
    @Test fun `insufficient and duplicate pins fall back to defaults`() {
        assertEquals(DEFAULT_PINNED_NAVIGATION_ITEMS, normalizePinnedNavigationItems(emptyList()))
        assertEquals(
            DEFAULT_PINNED_NAVIGATION_ITEMS,
            normalizePinnedNavigationItems(List(3) { NavigationItem.PERSONAL }),
        )
    }

    @Test fun `pins preserve incoming order deduplicate and never exceed five`() {
        assertEquals(
            NavigationItem.entries.reversed().take(5),
            normalizePinnedNavigationItems(NavigationItem.entries.reversed()),
        )
        assertEquals(
            listOf(NavigationItem.SHARES, NavigationItem.PERSONAL, NavigationItem.RECENTS),
            normalizePinnedNavigationItems(
                listOf(NavigationItem.SHARES, NavigationItem.PERSONAL, NavigationItem.SHARES, NavigationItem.RECENTS),
            ),
        )
    }
}
