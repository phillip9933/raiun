package eu.opencloud.android.next.core.datastore

/** Default destination order; unpinned destinations remain available in the menu. */
enum class NavigationItem { RECENTS, FAVORITES, PERSONAL, SHARES, SPACES, OFFLINE, TRANSFERS }

const val MIN_PINNED_NAVIGATION_ITEMS = 3
const val MAX_PINNED_NAVIGATION_ITEMS = 5
val DEFAULT_PINNED_NAVIGATION_ITEMS =
    listOf(
        NavigationItem.RECENTS,
        NavigationItem.FAVORITES,
        NavigationItem.PERSONAL,
        NavigationItem.SHARES,
        NavigationItem.SPACES,
    )

fun normalizePinnedNavigationItems(items: List<NavigationItem>): List<NavigationItem> =
    items
        .distinct()
        .take(MAX_PINNED_NAVIGATION_ITEMS)
        .takeIf { it.size >= MIN_PINNED_NAVIGATION_ITEMS } ?: DEFAULT_PINNED_NAVIGATION_ITEMS
