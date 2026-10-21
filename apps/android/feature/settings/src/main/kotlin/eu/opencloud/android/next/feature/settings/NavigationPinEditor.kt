package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.DragHandle
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.zIndex
import eu.opencloud.android.next.core.datastore.MAX_PINNED_NAVIGATION_ITEMS
import eu.opencloud.android.next.core.datastore.MIN_PINNED_NAVIGATION_ITEMS
import eu.opencloud.android.next.core.datastore.NavigationItem
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

/** A live draft is reordered while dragging; a cancelled gesture restores its starting order. */
@Composable
internal fun NavigationPinEditor(
    draft: List<NavigationItem>,
    onChange: (List<NavigationItem>) -> Unit,
) {
    val listState = rememberLazyListState()
    val currentDraft by rememberUpdatedState(draft)
    val change by rememberUpdatedState(onChange)
    val drag = remember { NavigationDragState(listState, { currentDraft }, { change(it) }) }
    NavigationDragAutoScroll(drag, listState)
    LazyColumn(state = listState) {
        item { Text(stringResource(R.string.settings_navigation_hint)) }
        items(draft + NavigationItem.entries.filterNot { it in draft }, key = { it.name }) { item ->
            val info = listState.layoutInfo.visibleItemsInfo.firstOrNull { it.key == item.name }
            val dragging = drag.item == item
            NavigationPinRow(
                item = item,
                draft = draft,
                onChange = onChange,
                modifier =
                    Modifier
                        .animateItem(
                            placementSpec =
                                if (dragging) {
                                    null
                                } else {
                                    androidx.compose.animation.core
                                        .spring()
                                },
                        ).zIndex(if (dragging) 1f else 0f)
                        .graphicsLayer {
                            translationY = if (dragging) drag.position - (info?.offset ?: 0) else 0f
                            shadowElevation = if (dragging) OpenCloudDimensions.ElevationMedium.toPx() else 0f
                        },
                dragModifier = Modifier.navigationDragHandle(item, drag),
            )
        }
    }
}

@Composable
private fun NavigationPinRow(
    item: NavigationItem,
    draft: List<NavigationItem>,
    onChange: (List<NavigationItem>) -> Unit,
    modifier: Modifier = Modifier,
    dragModifier: Modifier = Modifier,
) {
    val selected = item in draft
    val label = stringResource(item.navigationLabel())
    val index = draft.indexOf(item)
    val dragLabel = stringResource(R.string.settings_navigation_drag, label)
    val up = stringResource(R.string.settings_navigation_move_up, label)
    val down = stringResource(R.string.settings_navigation_move_down, label)
    ListItem(
        modifier = modifier,
        headlineContent = { Text(label) },
        colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHigh),
        leadingContent =
            if (selected) {
                {
                    Box(
                        modifier =
                            dragModifier.size(OpenCloudDimensions.TouchTarget).semantics {
                                contentDescription = dragLabel
                                customActions =
                                    buildList {
                                        if (index >
                                            0
                                        ) {
                                            add(
                                                CustomAccessibilityAction(up) {
                                                    onChange(draft.movePin(index, index - 1))
                                                    true
                                                },
                                            )
                                        }
                                        if (index <
                                            draft.lastIndex
                                        ) {
                                            add(
                                                CustomAccessibilityAction(down) {
                                                    onChange(
                                                        draft.movePin(
                                                            index,
                                                            index + 1,
                                                        ),
                                                    )
                                                    ; true
                                                },
                                            )
                                        }
                                    }
                            },
                        contentAlignment = Alignment.Center,
                    ) {
                        Icon(
                            Icons.Default.DragHandle,
                            contentDescription = null,
                            modifier = Modifier.size(OpenCloudDimensions.IconMedium),
                        )
                    }
                }
            } else {
                null
            },
        trailingContent = {
            Switch(
                checked = selected,
                modifier = Modifier.semantics { contentDescription = label },
                enabled =
                    if (selected) {
                        draft.size > MIN_PINNED_NAVIGATION_ITEMS
                    } else {
                        draft.size <
                            MAX_PINNED_NAVIGATION_ITEMS
                    },
                onCheckedChange = { checked -> onChange(if (checked) draft + item else draft - item) },
            )
        },
    )
}

private fun List<NavigationItem>.movePin(
    from: Int,
    to: Int,
): List<NavigationItem> = toMutableList().apply { add(to, removeAt(from)) }

private fun NavigationItem.navigationLabel() =
    when (this) {
        NavigationItem.RECENTS -> R.string.settings_navigation_recents
        NavigationItem.FAVORITES -> R.string.settings_navigation_favorites
        NavigationItem.PERSONAL -> R.string.settings_navigation_personal
        NavigationItem.SHARES -> R.string.settings_navigation_shares
        NavigationItem.SPACES -> R.string.settings_navigation_spaces
        NavigationItem.OFFLINE -> R.string.settings_navigation_offline
        NavigationItem.TRANSFERS -> R.string.settings_navigation_transfers
    }
