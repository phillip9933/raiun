package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.FormatListBulleted
import androidx.compose.material.icons.filled.GridView
import androidx.compose.material.icons.filled.ViewHeadline
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

/** Shared presentation; each source retains its own identity, access checks and actions. */
@Composable
// Changing layout deliberately recreates transient row UI; durable state belongs to the source.
@Suppress("LongParameterList", "ContentSlotReused")
fun <T> BrowserContent(
    entries: List<T>,
    key: (T) -> Any,
    layout: SettingsBrowserLayout,
    modifier: Modifier = Modifier,
    padding: PaddingValues = PaddingValues(),
    notice: (@Composable () -> Unit)? = null,
    footer: (@Composable () -> Unit)? = null,
    entry: @Composable (T) -> Unit,
) {
    if (layout == SettingsBrowserLayout.TILES) {
        LazyVerticalGrid(
            columns = GridCells.Fixed(2),
            modifier = modifier.fillMaxSize(),
            contentPadding =
                PaddingValues(
                    start = OpenCloudDimensions.SpacingMd,
                    top = padding.calculateTopPadding() + OpenCloudDimensions.SpacingMd,
                    end = OpenCloudDimensions.SpacingMd,
                    bottom = padding.calculateBottomPadding() + OpenCloudDimensions.ContentBottomClearance,
                ),
            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
        ) {
            if (notice != null) item(span = { GridItemSpan(maxLineSpan) }) { notice() }
            items(entries, key = key) { entry(it) }
            if (footer != null) item(span = { GridItemSpan(maxLineSpan) }) { footer() }
        }
    } else {
        LazyColumn(
            modifier = modifier.fillMaxSize(),
            contentPadding =
                PaddingValues(
                    top = padding.calculateTopPadding(),
                    bottom = padding.calculateBottomPadding() + OpenCloudDimensions.ContentBottomClearance,
                ),
        ) {
            if (notice != null) item { notice() }
            items(entries, key = key) { entry(it) }
            if (footer != null) item { footer() }
        }
    }
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
// Changing layout deliberately recreates transient row UI; durable state belongs to the source.
@Suppress("LongParameterList", "ContentSlotReused")
fun BrowserEntry(
    layout: SettingsBrowserLayout,
    onOpen: () -> Unit,
    name: @Composable () -> Unit,
    thumbnail: @Composable (Modifier) -> Unit,
    metadata: @Composable () -> Unit,
    actions: @Composable () -> Unit,
    modifier: Modifier = Modifier,
    selected: Boolean = false,
    onLongClick: (() -> Unit)? = null,
) {
    val click = modifier.combinedClickable(onClick = onOpen, onLongClick = onLongClick)
    when (layout) {
        SettingsBrowserLayout.TILES ->
            Card(
                modifier = Modifier.aspectRatio(1f).then(click),
                colors =
                    CardDefaults.cardColors(
                        containerColor =
                            if (selected) {
                                MaterialTheme.colorScheme.secondaryContainer
                            } else {
                                MaterialTheme.colorScheme.surfaceContainer
                            },
                    ),
            ) {
                Column(Modifier.fillMaxSize()) {
                    Row(
                        Modifier.fillMaxWidth().padding(start = OpenCloudDimensions.SpacingSm),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Box(Modifier.weight(1f)) { name() }
                        actions()
                    }
                    Box(Modifier.fillMaxWidth().weight(1f).clipToBounds(), contentAlignment = Alignment.Center) {
                        thumbnail(Modifier.fillMaxSize())
                    }
                    Box(Modifier.padding(OpenCloudDimensions.SpacingSm)) { metadata() }
                }
            }
        SettingsBrowserLayout.CONDENSED_TABLE ->
            Row(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = OpenCloudDimensions.CondensedRowHeight)
                        .background(
                            if (selected) {
                                MaterialTheme.colorScheme.secondaryContainer
                            } else {
                                OpenCloudColor.Transparent
                            },
                        ).then(click)
                        .padding(horizontal = OpenCloudDimensions.SpacingXs),
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                thumbnail(Modifier.size(OpenCloudDimensions.IconMedium))
                Column(Modifier.weight(1f)) {
                    name()
                    metadata()
                }
                actions()
            }
        SettingsBrowserLayout.DEFAULT_TABLE ->
            ListItem(
                headlineContent = name,
                supportingContent = metadata,
                leadingContent = { thumbnail(Modifier.size(OpenCloudDimensions.TouchTarget)) },
                trailingContent = actions,
                colors =
                    ListItemDefaults.colors(
                        containerColor =
                            when {
                                selected -> MaterialTheme.colorScheme.secondaryContainer
                                else -> OpenCloudColor.Transparent
                            },
                    ),
                modifier = Modifier.fillMaxWidth().then(click),
            )
    }
}

@Composable
@Suppress("LongParameterList") // Navigation, layout action and source-specific title/sort slot.
fun BrowserToolbar(
    canNavigateUp: Boolean,
    layout: SettingsBrowserLayout,
    onNavigateUp: () -> Unit,
    onToggleLayout: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable RowScope.() -> Unit,
) {
    Column(modifier) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingXs),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (canNavigateUp) {
                IconButton(onClick = onNavigateUp) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.browser_parent))
                }
            }
            Row(Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically, content = content)
            IconButton(onClick = onToggleLayout) {
                val (icon, description) =
                    when (layout) {
                        SettingsBrowserLayout.DEFAULT_TABLE -> Icons.Default.ViewHeadline to R.string.browser_compact
                        SettingsBrowserLayout.CONDENSED_TABLE -> Icons.Default.GridView to R.string.browser_tiles
                        SettingsBrowserLayout.TILES ->
                            Icons.AutoMirrored.Filled.FormatListBulleted to
                                R.string.browser_regular
                    }
                Icon(icon, stringResource(description))
            }
        }
        HorizontalDivider()
    }
}
