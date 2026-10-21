package eu.opencloud.android.next.core.ui

data class BrowserPlacementBarState(
    val actionLabel: Int,
    val cancelLabel: Int,
    val busy: Boolean,
    val enabled: Boolean = true,
    val showCancel: Boolean = true,
)
