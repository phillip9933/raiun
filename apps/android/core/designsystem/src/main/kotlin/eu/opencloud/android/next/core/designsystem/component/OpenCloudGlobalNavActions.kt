package eu.opencloud.android.next.core.designsystem.component

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.vector.PathParser
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import eu.opencloud.android.next.core.designsystem.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.ResourceKind

data class OpenCloudGlobalNavActions(
    val onMenu: () -> Unit = {},
    val onSearch: () -> Unit = {},
    val onFeedback: () -> Unit = {},
    val onNotifications: () -> Unit = {},
    val onProfile: () -> Unit = {},
)

@Composable
fun OpenCloudGlobalTopBar(
    displayName: String,
    actions: OpenCloudGlobalNavActions,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier =
            modifier
                .fillMaxWidth()
                .height(OpenCloudDimensions.GlobalTopBarHeight)
                .background(OpenCloudColor.Surface),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        GlobalIconButton("Show navigation menu", actions.onMenu) { MenuIcon() }
        OpenCloudBrand()
        Spacer(modifier = Modifier.weight(1f))
        Row(
            horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            GlobalIconButton("Search", actions.onSearch) { SearchIcon() }
            GlobalIconButton("Share feedback", actions.onFeedback) {
                OpenCloudWebIcon(OpenCloudWebIconType.Feedback)
            }
            GlobalIconButton("Notifications", actions.onNotifications) { NotificationIcon() }
        }
        Box(
            modifier =
                Modifier
                    .padding(horizontal = OpenCloudDimensions.SpacingXxs)
                    .size(OpenCloudDimensions.AvatarSize)
                    .clip(CircleShape)
                    .background(OpenCloudColor.PrimaryContainer)
                    .clickable(role = Role.Button, onClick = actions.onProfile)
                    .semantics { contentDescription = "Open profile menu" },
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = initials(displayName),
                color = OpenCloudColor.OnPrimaryContainer,
                style = MaterialTheme.typography.bodySmall,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
fun OpenCloudCheckbox(
    checked: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier =
            modifier
                .size(OpenCloudDimensions.TouchTarget)
                .clickable(role = Role.Checkbox, onClick = onClick)
                .semantics { selected = checked },
        contentAlignment = Alignment.Center,
    ) {
        Canvas(modifier = Modifier.size(OpenCloudDimensions.CheckboxSize)) {
            val radius = OpenCloudDimensions.CheckboxCornerRadius.toPx()
            drawRoundRect(
                color = if (checked) OpenCloudColor.Primary else OpenCloudColor.Transparent,
                cornerRadius =
                    androidx.compose.ui.geometry
                        .CornerRadius(radius),
            )
            drawRoundRect(
                color = if (checked) OpenCloudColor.Primary else OpenCloudColor.Outline.copy(alpha = 0.8f),
                cornerRadius =
                    androidx.compose.ui.geometry
                        .CornerRadius(radius),
                style = Stroke(width = OpenCloudDimensions.StrokeRegular.toPx()),
            )
            if (checked) {
                val check =
                    Path().apply {
                        moveTo(size.width * 0.22f, size.height * 0.52f)
                        lineTo(size.width * 0.43f, size.height * 0.72f)
                        lineTo(size.width * 0.79f, size.height * 0.31f)
                    }
                drawPath(
                    check,
                    OpenCloudColor.OnPrimary,
                    style =
                        Stroke(
                            OpenCloudDimensions.StrokeCheckmark.toPx(),
                            cap = StrokeCap.Round,
                            join = StrokeJoin.Round,
                        ),
                )
            }
        }
    }
}

@Composable
fun OpenCloudResourceIcon(
    kind: ResourceKind,
    modifier: Modifier = Modifier,
    size: Dp = OpenCloudDimensions.IconMedium,
) {
    Canvas(
        modifier =
            modifier
                .size(size)
                .semantics { contentDescription = if (kind == ResourceKind.FOLDER) "Folder" else "File" },
    ) {
        if (kind == ResourceKind.FOLDER) {
            val folder =
                Path().apply {
                    moveTo(this@Canvas.size.width * 0.08f, this@Canvas.size.height * 0.25f)
                    lineTo(this@Canvas.size.width * 0.39f, this@Canvas.size.height * 0.25f)
                    lineTo(this@Canvas.size.width * 0.49f, this@Canvas.size.height * 0.38f)
                    lineTo(this@Canvas.size.width * 0.92f, this@Canvas.size.height * 0.38f)
                    lineTo(this@Canvas.size.width * 0.92f, this@Canvas.size.height * 0.82f)
                    lineTo(this@Canvas.size.width * 0.08f, this@Canvas.size.height * 0.82f)
                    close()
                }
            drawPath(folder, OpenCloudColor.ResourceFolder)
        } else {
            val file =
                Path().apply {
                    moveTo(this@Canvas.size.width * 0.22f, this@Canvas.size.height * 0.08f)
                    lineTo(this@Canvas.size.width * 0.62f, this@Canvas.size.height * 0.08f)
                    lineTo(this@Canvas.size.width * 0.82f, this@Canvas.size.height * 0.29f)
                    lineTo(this@Canvas.size.width * 0.82f, this@Canvas.size.height * 0.92f)
                    lineTo(this@Canvas.size.width * 0.22f, this@Canvas.size.height * 0.92f)
                    close()
                }
            drawPath(file, OpenCloudColor.TertiaryContainer)
            drawPath(
                file,
                OpenCloudColor.Tertiary,
                style = Stroke(OpenCloudDimensions.StrokeThin.toPx(), join = StrokeJoin.Round),
            )
            drawLine(
                OpenCloudColor.Tertiary,
                Offset(size.toPx() * 0.36f, size.toPx() * 0.55f),
                Offset(
                    size.toPx() * 0.68f,
                    size.toPx() * 0.55f,
                ),
                OpenCloudDimensions.StrokeThin.toPx(),
            )
            drawLine(
                OpenCloudColor.Tertiary,
                Offset(size.toPx() * 0.36f, size.toPx() * 0.70f),
                Offset(
                    size.toPx() * 0.63f,
                    size.toPx() * 0.70f,
                ),
                OpenCloudDimensions.StrokeThin.toPx(),
            )
        }
    }
}

@Composable
fun OpenCloudFileListHeader(modifier: Modifier = Modifier) {
    Row(
        modifier =
            modifier
                .fillMaxWidth()
                .height(OpenCloudDimensions.ViewHeaderHeight)
                .padding(horizontal = OpenCloudDimensions.SpacingMd),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Spacer(modifier = Modifier.width(OpenCloudDimensions.ListNameIndent))
        Text(
            text = "Name ↓",
            modifier = Modifier.weight(1f),
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.SemiBold,
        )
        Text(
            text = "Actions",
            style = MaterialTheme.typography.bodySmall,
            color = OpenCloudColor.OnSurfaceVariant,
            fontWeight = FontWeight.SemiBold,
        )
    }
}

@Composable
fun OpenCloudFileBrowserFab(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier =
            modifier
                .shadow(OpenCloudDimensions.ElevationMedium, CircleShape)
                .size(OpenCloudDimensions.FabSize)
                .clip(CircleShape)
                .background(OpenCloudColor.Chrome)
                .clickable(role = Role.Button, onClick = onClick)
                .semantics { contentDescription = "New" },
        contentAlignment = Alignment.Center,
    ) {
        PlusIcon()
    }
}

@Composable
private fun OpenCloudBrand(modifier: Modifier = Modifier) {
    Image(
        painter = painterResource(R.drawable.raiun_crest),
        contentDescription = "Raiun",
        modifier =
            modifier.size(
                width = OpenCloudDimensions.BrandMarkWidth,
                height = OpenCloudDimensions.BrandMarkSize,
            ),
    )
}

@Composable
fun OpenCloudWebIcon(
    type: OpenCloudWebIconType,
    modifier: Modifier = Modifier,
) = Canvas(modifier.size(OpenCloudDimensions.IconMedium)) {
    val path = PathParser().parsePathString(type.pathData).toPath()
    withTransform({
        scale(
            scaleX = size.width / WEB_ICON_VIEWBOX,
            scaleY = size.height / WEB_ICON_VIEWBOX,
            pivot = Offset.Zero,
        )
    }) {
        drawPath(path, OpenCloudColor.OnSurface)
    }
}

enum class OpenCloudWebIconType(
    val pathData: String,
) {
    Feedback(
        "M6.45455 19L2 22.5V4C2 3.44772 2.44772 3 3 3H21C21.5523 3 22 3.44772 22 4V18C22 18.5523 21.5523 19 21 19H6.45455ZM4 18.3851L5.76282 17H20V5H4V18.3851ZM11 13H13V15H11V13ZM11 7H13V12H11V7Z",
    ),
    Settings(
        "M3.33946 17.0002C2.90721 16.2515 2.58277 15.4702 2.36133 14.6741C3.3338 14.1779 3.99972 13.1668 3.99972 12.0002C3.99972 10.8345 3.3348 9.824 2.36353 9.32741C2.81025 7.71651 3.65857 6.21627 4.86474 4.99001C5.7807 5.58416 6.98935 5.65534 7.99972 5.072C9.01009 4.48866 9.55277 3.40635 9.4962 2.31604C11.1613 1.8846 12.8847 1.90004 14.5031 2.31862C14.4475 3.40806 14.9901 4.48912 15.9997 5.072C17.0101 5.65532 18.2187 5.58416 19.1346 4.99007C19.7133 5.57986 20.2277 6.25151 20.66 7.00021C21.0922 7.7489 21.4167 8.53025 21.6381 9.32628C20.6656 9.82247 19.9997 10.8336 19.9997 12.0002C19.9997 13.166 20.6646 14.1764 21.6359 14.673C21.1892 16.2839 20.3409 17.7841 19.1347 19.0104C18.2187 18.4163 17.0101 18.3451 15.9997 18.9284C14.9893 19.5117 14.4467 20.5941 14.5032 21.6844C12.8382 22.1158 11.1148 22.1004 9.49633 21.6818C9.55191 20.5923 9.00929 19.5113 7.99972 18.9284C6.98938 18.3451 5.78079 18.4162 4.86484 19.0103C4.28617 18.4205 3.77172 17.7489 3.33946 17.0002ZM8.99972 17.1964C10.0911 17.8265 10.8749 18.8227 11.2503 19.9659C11.7486 20.0133 12.2502 20.014 12.7486 19.9675C13.1238 18.8237 13.9078 17.8268 14.9997 17.1964C16.0916 16.5659 17.347 16.3855 18.5252 16.6324C18.8146 16.224 19.0648 15.7892 19.2729 15.334C18.4706 14.4373 17.9997 13.2604 17.9997 12.0002C17.9997 10.74 18.4706 9.5632 19.2729 8.6665C19.1688 8.4405 19.0538 8.21822 18.9279 8.00021C18.802 7.78219 18.667 7.57148 18.5233 7.36842C17.3457 7.61476 16.0911 7.43414 14.9997 6.80405C13.9083 6.17395 13.1246 5.17768 12.7491 4.03455C12.2509 3.98714 11.7492 3.98646 11.2509 4.03292C10.8756 5.17671 10.0916 6.17364 8.99972 6.80405C7.9078 7.43447 6.65245 7.61494 5.47428 7.36803C5.18485 7.77641 4.93463 8.21117 4.72656 8.66637C5.52881 9.56311 5.99972 10.74 5.99972 12.0002C5.99972 13.2604 5.52883 14.4372 4.72656 15.3339C4.83067 15.5599 4.94564 15.7822 5.07152 16.0002C5.19739 16.2182 5.3324 16.4289 5.47612 16.632C6.65377 16.3857 7.90838 16.5663 8.99972 17.1964ZM11.9997 15.0002C10.3429 15.0002 8.99972 13.6571 8.99972 12.0002C8.99972 10.3434 10.3429 9.00021 11.9997 9.00021C13.6566 9.00021 14.9997 10.3434 14.9997 12.0002C14.9997 13.6571 13.6566 15.0002 11.9997 15.0002ZM11.9997 13.0002C12.552 13.0002 12.9997 12.5525 12.9997 12.0002C12.9997 11.4479 12.552 11.0002 11.9997 11.0002C11.4474 11.0002 10.9997 11.4479 10.9997 12.0002C10.9997 12.5525 11.4474 13.0002 11.9997 13.0002Z",
    ),
    Folder(
        "M2 4C2 3.44772 2.44772 3 3 3H10.4142L12.4142 5H21C21.5523 5 22 5.44772 22 6V20C22 20.5523 21.5523 21 21 21L3 21C2.45 21 2 20.55 2 20V4ZM10.5858 6L9.58579 5H4V7H9.58579L10.5858 6ZM4 9V19L20 19V7H12.4142L10.4142 9H4Z",
    ),
    Star(
        "M12.0006 18.26L4.94715 22.2082L6.52248 14.2799L0.587891 8.7918L8.61493 7.84006L12.0006 0.5L15.3862 7.84006L23.4132 8.7918L17.4787 14.2799L19.054 22.2082L12.0006 18.26ZM12.0006 15.968L16.2473 18.3451L15.2988 13.5717L18.8719 10.2674L14.039 9.69434L12.0006 5.27502L9.96214 9.69434L5.12921 10.2674L8.70231 13.5717L7.75383 18.3451L12.0006 15.968Z",
    ),
    Share(
        "M13 14H11C7.54202 14 4.53953 15.9502 3.03239 18.8107C3.01093 18.5433 3 18.2729 3 18C3 12.4772 7.47715 8 13 8V2.5L23.5 11L13 19.5V14ZM11 12H15V15.3078L20.3214 11L15 6.69224V10H13C10.5795 10 8.41011 11.0749 6.94312 12.7735C8.20873 12.2714 9.58041 12 11 12Z",
    ),
    Spaces(
        "M21 3C21.5523 3 22 3.44772 22 4V20C22 20.5523 21.5523 21 21 21H3C2.44772 21 2 20.5523 2 20V4C2 3.44772 2.44772 3 3 3H21ZM11 13H4V19H11V13ZM20 13H13V19H20V13ZM11 5H4V11H11V5ZM20 5H13V11H20V5Z",
    ),
    Deleted(
        "M4 8H20V21C20 21.5523 19.5523 22 19 22H5C4.44772 22 4 21.5523 4 21V8ZM6 10V20H18V10H6ZM9 12H11V18H9V12ZM13 12H15V18H13V12ZM7 5V3C7 2.44772 7.44772 2 8 2H16C16.5523 2 17 2.44772 17 3V5H22V7H2V5H7ZM9 4V5H15V4H9Z",
    ),
    DefaultTable(
        "M8 4H21V6H8V4ZM4.5 6.5C3.67157 6.5 3 5.82843 3 5C3 4.17157 3.67157 3.5 4.5 3.5C5.32843 3.5 6 4.17157 6 5C6 5.82843 5.32843 6.5 4.5 6.5ZM4.5 13.5C3.67157 13.5 3 12.8284 3 12C3 11.1716 3.67157 10.5 4.5 10.5C5.32843 10.5 6 11.1716 6 12C6 12.8284 5.32843 13.5 4.5 13.5ZM4.5 20.4C3.67157 20.4 3 19.7284 3 18.9C3 18.0716 3.67157 17.4 4.5 17.4C5.32843 17.4 6 18.0716 6 18.9C6 19.7284 5.32843 20.4 4.5 20.4ZM8 11H21V13H8V11ZM8 18H21V20H8V18Z",
    ),
    CondensedTable("M3 5H21V7H3V5ZM3 9H21V11H3V9ZM3 17H21V19H3V17ZM21 13H3V15H21V13Z"),
    Tiles(
        "M3 3C2.44772 3 2 3.44772 2 4V10C2 10.5523 2.44772 11 3 11H10C10.5523 11 11 10.5523 11 10V4C11 3.44772 10.5523 3 10 3H3ZM4 9V5H9V9H4ZM3 13C2.44772 13 2 13.4477 2 14V20C2 20.5523 2.44772 21 3 21H10C10.5523 21 11 20.5523 11 20V14C11 13.4477 10.5523 13 10 13H3ZM4 19V15H9V19H4ZM13 4C13 3.44772 13.4477 3 14 3H21C21.5523 3 22 3.44772 22 4V10C22 10.5523 21.5523 11 21 11H14C13.4477 11 13 10.5523 13 10V4ZM15 5V9H20V5H15ZM14 13C13.4477 13 13 13.4477 13 14V20C13 20.5523 13.4477 21 14 21H21C21.5523 21 22 20.5523 22 20V14C22 13.4477 21.5523 13 21 13H14ZM15 19V15H20V19H15Z",
    ),
    Close(
        "M11.9997 10.5865L16.9495 5.63672L18.3637 7.05093L13.4139 12.0007L18.3637 16.9504L16.9495 18.3646L11.9997 13.4149L7.04996 18.3646L5.63574 16.9504L10.5855 12.0007L5.63574 7.05093L7.04996 5.63672L11.9997 10.5865Z",
    ),
    ArrowLeftS(
        "M10.8284 12.0007L15.7782 16.9504L14.364 18.3646L8 12.0007L14.364 5.63672L15.7782 7.05093L10.8284 12.0007Z",
    ),
}

@Composable
private fun GlobalIconButton(
    description: String,
    onClick: () -> Unit,
    icon: @Composable () -> Unit,
) = Box(
    modifier =
        Modifier
            .size(
                OpenCloudDimensions.TopBarActionSize,
            ).clickable(role = Role.Button, onClick = onClick)
            .semantics {
                contentDescription =
                    description
            },
    contentAlignment = Alignment.Center,
) { icon() }

@Composable
private fun MenuIcon() =
    Canvas(Modifier.size(OpenCloudDimensions.IconMedium)) {
        repeat(3) { index ->
            val y = size.height * (0.25f + index * 0.25f)
            drawLine(
                color = OpenCloudColor.OnSurface,
                start = Offset(size.width * 0.12f, y),
                end = Offset(size.width * 0.88f, y),
                strokeWidth = OpenCloudDimensions.StrokeEmphasis.toPx(),
                cap = StrokeCap.Round,
            )
        }
    }

@Composable
private fun SearchIcon() =
    Canvas(Modifier.size(OpenCloudDimensions.IconMedium)) {
        drawCircle(
            OpenCloudColor.OnSurface,
            size.minDimension * 0.28f,
            Offset(size.width * 0.44f, size.height * 0.44f),
            style = Stroke(OpenCloudDimensions.StrokeRegular.toPx()),
        )
        drawLine(
            OpenCloudColor.OnSurface,
            Offset(size.width * 0.64f, size.height * 0.64f),
            Offset(
                size.width * 0.86f,
                size.height * 0.86f,
            ),
            OpenCloudDimensions.StrokeRegular.toPx(),
            StrokeCap.Round,
        )
    }

@Composable
private fun NotificationIcon() =
    Canvas(Modifier.size(OpenCloudDimensions.IconMedium)) {
        val bell =
            Path().apply {
                moveTo(size.width * 0.22f, size.height * 0.72f)
                quadraticTo(size.width * 0.32f, size.height * 0.62f, size.width * 0.32f, size.height * 0.43f)
                cubicTo(
                    size.width * 0.32f,
                    size.height * 0.20f,
                    size.width * 0.68f,
                    size.height * 0.20f,
                    size.width * 0.68f,
                    size.height * 0.43f,
                )
                quadraticTo(size.width * 0.68f, size.height * 0.62f, size.width * 0.78f, size.height * 0.72f)
                close()
            }
        drawPath(
            bell,
            OpenCloudColor.OnSurface,
            style =
                Stroke(
                    OpenCloudDimensions.StrokeRegular.toPx(),
                    cap = StrokeCap.Round,
                    join = StrokeJoin.Round,
                ),
        )
        drawArc(
            color = OpenCloudColor.OnSurface,
            startAngle = 0f,
            sweepAngle = 180f,
            useCenter = false,
            topLeft = Offset(size.width * 0.43f, size.height * 0.72f),
            size = Size(size.width * 0.14f, size.height * 0.13f),
            style = Stroke(OpenCloudDimensions.StrokeRegular.toPx(), cap = StrokeCap.Round),
        )
    }

@Composable
private fun PlusIcon() =
    Canvas(Modifier.size(OpenCloudDimensions.IconMedium)) {
        drawLine(
            OpenCloudColor.OnPrimary,
            Offset(size.width * 0.22f, size.height * 0.50f),
            Offset(
                size.width * 0.78f,
                size.height * 0.50f,
            ),
            OpenCloudDimensions.StrokeRegular.toPx(),
        )
        drawLine(
            OpenCloudColor.OnPrimary,
            Offset(size.width * 0.50f, size.height * 0.22f),
            Offset(
                size.width * 0.50f,
                size.height * 0.78f,
            ),
            OpenCloudDimensions.StrokeRegular.toPx(),
        )
    }

private fun initials(displayName: String): String =
    displayName
        .trim()
        .split(Regex("\\s+"))
        .filter(String::isNotBlank)
        .take(2)
        .mapNotNull { it.firstOrNull()?.uppercase() }
        .joinToString("")
        .ifBlank { "OC" }

private const val WEB_ICON_VIEWBOX = 24f
