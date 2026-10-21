package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.BoundaryEntry

/** Route-owned references are never saved; losing the unlock lease invalidates the request. */
internal data class BoundaryTransferRequest(
    val accountId: String,
    val move: Boolean,
    val ordinary: List<ResourceEntity> = emptyList(),
    val unlocked: Pair<BoundaryEndpoint, BoundaryEntry>? = null,
    val onComplete: () -> Unit = {},
)
