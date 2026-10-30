package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

data class BrowserPageNavigationState(
    val first: Long,
    val last: Long,
    val total: Long,
    val hasPrevious: Boolean,
    val hasNext: Boolean,
)

/** Native controls retain their own space; narrow or enlarged text gives the range a separate row. */
@Composable
fun BrowserPageNavigation(
    state: BrowserPageNavigationState,
    onPage: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    val fontScale = LocalDensity.current.fontScale
    val range = stringResource(R.string.browser_page_range, state.first, state.last, state.total)
    BoxWithConstraints(modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingSm)) {
        if (maxWidth < OpenCloudDimensions.PageNavigationMinInlineWidth || fontScale >= STACKED_PAGE_FONT_SCALE) {
            Column {
                Text(
                    range,
                    Modifier.fillMaxWidth(),
                    style = MaterialTheme.typography.labelMedium,
                    textAlign = TextAlign.Center,
                )
                Row(Modifier.fillMaxWidth()) {
                    PageButton(true, state.hasPrevious, onPage, Modifier.weight(1f))
                    PageButton(false, state.hasNext, onPage, Modifier.weight(1f))
                }
            }
        } else {
            Row(
                Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                PageButton(true, state.hasPrevious, onPage)
                Text(
                    range,
                    Modifier.weight(1f),
                    style = MaterialTheme.typography.labelMedium,
                    textAlign = TextAlign.Center,
                )
                PageButton(false, state.hasNext, onPage)
            }
        }
    }
}

@Composable
private fun PageButton(
    previous: Boolean,
    enabled: Boolean,
    onPage: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    TextButton(onClick = { onPage(previous) }, enabled = enabled, modifier = modifier) {
        Text(stringResource(if (previous) R.string.browser_previous_page else R.string.browser_next_page))
    }
}

private const val STACKED_PAGE_FONT_SCALE = 1.5f
