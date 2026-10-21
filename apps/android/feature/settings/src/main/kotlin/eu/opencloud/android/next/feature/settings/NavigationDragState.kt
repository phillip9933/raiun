package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.scrollBy
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import eu.opencloud.android.next.core.datastore.NavigationItem
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

internal class NavigationDragState(
    private val list: LazyListState,
    private val draft: () -> List<NavigationItem>,
    private val change: (List<NavigationItem>) -> Unit,
) {
    var item by mutableStateOf<NavigationItem?>(null)
        private set
    var position by mutableFloatStateOf(0f)
        private set
    private var size = 0f
    private var original = emptyList<NavigationItem>()

    fun start(pin: NavigationItem) {
        if (pin !in draft()) return
        val row = list.layoutInfo.visibleItemsInfo.firstOrNull { it.key == pin.name } ?: return
        original = draft()
        item = pin
        position = row.offset.toFloat()
        size = row.size.toFloat()
    }

    fun stop(cancelled: Boolean) {
        if (cancelled && item != null) change(original)
        item = null
    }

    fun move(distance: Float) {
        val layout = list.layoutInfo
        val start = layout.viewportStartOffset.toFloat()
        val end = (layout.viewportEndOffset - size).coerceAtLeast(start)
        position = (position + distance).coerceIn(start, end)
        reorder()
    }

    fun reorder() {
        val current = draft()
        val center = position + size / 2f
        val target =
            list.layoutInfo.visibleItemsInfo.firstOrNull {
                center >= it.offset && center < it.offset + it.size && current.any { pin -> pin.name == it.key }
            }
        val from = item?.let { current.indexOf(it) } ?: -1
        val to = current.indexOfFirst { it.name == target?.key }
        if (from >= 0 && to >= 0 && from != to) {
            change(current.toMutableList().apply { add(to, removeAt(from)) })
        }
    }

    fun scrollStep(): Float {
        val layout = list.layoutInfo
        return when {
            position < layout.viewportStartOffset + size / 2f -> -size / 8f
            position + size > layout.viewportEndOffset - size / 2f -> size / 8f
            else -> 0f
        }
    }
}

@Composable
internal fun NavigationDragAutoScroll(
    drag: NavigationDragState,
    list: LazyListState,
) {
    LaunchedEffect(drag.item) {
        while (drag.item != null && isActive) {
            delay(16)
            list.scrollBy(drag.scrollStep())
            drag.reorder()
        }
    }
}

internal fun Modifier.navigationDragHandle(
    pin: NavigationItem,
    drag: NavigationDragState,
): Modifier =
    pointerInput(pin, drag) {
        detectDragGestures(
            onDragStart = { drag.start(pin) },
            onDragEnd = { drag.stop(cancelled = false) },
            onDragCancel = { drag.stop(cancelled = true) },
        ) { event, amount ->
            if (drag.item == pin) {
                event.consume()
                drag.move(amount.y)
            }
        }
    }
