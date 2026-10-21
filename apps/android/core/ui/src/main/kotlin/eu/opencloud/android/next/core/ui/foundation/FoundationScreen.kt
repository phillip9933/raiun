package eu.opencloud.android.next.core.ui.foundation

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import eu.opencloud.android.next.core.designsystem.theme.LocalOpenCloudExtendedColors
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.model.Resource
import eu.opencloud.android.next.core.model.ResourceKind

private val previewResources =
    listOf(
        Resource("documents", "Documents", ResourceKind.FOLDER, "Modified today"),
        Resource("pictures", "Pictures", ResourceKind.FOLDER, "Modified yesterday"),
        Resource("welcome", "Welcome to OpenCloud.pdf", ResourceKind.FILE, "1.2 MB · Modified Sep 5"),
    )

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongMethod")
fun FoundationScreen(modifier: Modifier = Modifier) {
    var actionsOpen by remember { mutableStateOf(false) }
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)

    Scaffold(
        modifier = modifier,
        containerColor = OpenCloudColor.Background,
        topBar = {
            TopAppBar(
                colors =
                    TopAppBarDefaults.topAppBarColors(
                        containerColor = LocalOpenCloudExtendedColors.current.chrome,
                        titleContentColor = LocalOpenCloudExtendedColors.current.onChrome,
                        navigationIconContentColor = LocalOpenCloudExtendedColors.current.onChrome,
                        actionIconContentColor = LocalOpenCloudExtendedColors.current.onChrome,
                    ),
                navigationIcon = {
                    IconButton(onClick = {}) {
                        Text("☰", style = MaterialTheme.typography.headlineSmall)
                    }
                },
                title = { Text("openCloud", fontWeight = FontWeight.SemiBold) },
                actions = {
                    IconButton(onClick = {}) {
                        Text("◉", style = MaterialTheme.typography.titleMedium)
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                containerColor = OpenCloudColor.Transparent,
                contentColor = OpenCloudColor.OnPrimary,
                onClick = { actionsOpen = true },
                modifier =
                    Modifier
                        .semantics {
                            contentDescription = "Create or upload"
                            role = Role.Button
                        }.clip(RoundedCornerShape(OpenCloudDimensions.FabCornerRadius))
                        .background(
                            Brush.horizontalGradient(
                                listOf(OpenCloudColor.Secondary, OpenCloudColor.Primary),
                            ),
                        ),
            ) {
                Text("+", style = MaterialTheme.typography.headlineSmall)
            }
        },
    ) { innerPadding ->
        Box(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .padding(
                        horizontal = OpenCloudDimensions.SpacingXs,
                        vertical = OpenCloudDimensions.SpacingXs,
                    ).clip(RoundedCornerShape(OpenCloudDimensions.ContentCornerRadius))
                    .background(OpenCloudColor.SurfaceContainer),
        ) {
            Card(
                modifier = Modifier.fillMaxSize(),
                shape = RoundedCornerShape(OpenCloudDimensions.ContentCornerRadius),
                colors = CardDefaults.cardColors(containerColor = OpenCloudColor.Surface),
                elevation = CardDefaults.cardElevation(defaultElevation = OpenCloudDimensions.ElevationNone),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    MobileBreadcrumb(currentFolder = "Personal")
                    LazyColumn(
                        contentPadding = PaddingValues(bottom = OpenCloudDimensions.ContentBottomClearance),
                    ) {
                        items(previewResources, key = Resource::id) { resource ->
                            ResourceRow(resource = resource, onActionsClick = { actionsOpen = true })
                        }
                    }
                }
            }
        }
    }

    if (actionsOpen) {
        ModalBottomSheet(
            sheetState = sheetState,
            onDismissRequest = { actionsOpen = false },
            containerColor = OpenCloudColor.SurfaceContainerHigh,
            contentColor = OpenCloudColor.OnSurface,
            shape =
                RoundedCornerShape(
                    topStart = OpenCloudDimensions.ContentCornerRadius,
                    topEnd = OpenCloudDimensions.ContentCornerRadius,
                ),
        ) {
            Column(
                modifier =
                    Modifier
                        .fillMaxWidth()
                        .padding(bottom = OpenCloudDimensions.SpacingXl),
            ) {
                Row(
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .padding(
                                horizontal = OpenCloudDimensions.SpacingMd,
                                vertical = OpenCloudDimensions.SpacingSm,
                            ),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text("Actions", style = MaterialTheme.typography.titleMedium)
                    IconButton(
                        onClick = { actionsOpen = false },
                    ) { Text("×", style = MaterialTheme.typography.headlineSmall) }
                }
                ActionRow("Upload files")
                ActionRow("Create folder")
            }
        }
    }
}

@Composable
private fun MobileBreadcrumb(currentFolder: String) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .height(OpenCloudDimensions.TouchTarget)
                .padding(horizontal = OpenCloudDimensions.SpacingSm),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier =
                Modifier
                    .size(OpenCloudDimensions.TouchTarget)
                    .semantics { contentDescription = "Navigate one level up" },
            contentAlignment = Alignment.Center,
        ) {
            Text("‹", style = MaterialTheme.typography.headlineSmall)
        }
        Text(
            text = currentFolder,
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Spacer(modifier = Modifier.width(OpenCloudDimensions.TouchTarget))
    }
}

@Composable
private fun ResourceRow(
    resource: Resource,
    onActionsClick: () -> Unit,
) {
    Row(
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(role = Role.Button) {}
                .padding(
                    horizontal = OpenCloudDimensions.SpacingMd,
                    vertical = OpenCloudDimensions.SpacingXs,
                ),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        ResourceGlyph(resource.kind)
        Spacer(modifier = Modifier.width(OpenCloudDimensions.SpacingXs))
        Column(modifier = Modifier.weight(1f)) {
            Text(resource.name, style = MaterialTheme.typography.bodyLarge)
            Text(
                resource.metadata,
                color = OpenCloudColor.OnSurfaceVariant,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
        IconButton(onClick = onActionsClick) {
            Text("⋮", style = MaterialTheme.typography.headlineSmall)
        }
    }
}

@Composable
private fun ResourceGlyph(kind: ResourceKind) {
    val color = if (kind == ResourceKind.FOLDER) OpenCloudColor.Primary else OpenCloudColor.Tertiary
    Box(
        modifier =
            Modifier
                .size(OpenCloudDimensions.IconMedium)
                .drawBehind {
                    drawCircle(
                        color = color,
                        radius = size.minDimension / 2f,
                        style = Stroke(width = OpenCloudDimensions.StrokeRegular.toPx()),
                    )
                },
    )
}

@Composable
private fun ActionRow(label: String) {
    Text(
        text = label,
        modifier =
            Modifier
                .fillMaxWidth()
                .clickable(role = Role.Button) {}
                .padding(
                    horizontal = OpenCloudDimensions.SpacingMd,
                    vertical = OpenCloudDimensions.SpacingMd,
                ),
        style = MaterialTheme.typography.bodyLarge,
    )
}

@Preview(widthDp = 360, heightDp = 800, showBackground = true)
@Composable
private fun FoundationScreenPreview() {
    OpenCloudTheme {
        FoundationScreen()
    }
}
