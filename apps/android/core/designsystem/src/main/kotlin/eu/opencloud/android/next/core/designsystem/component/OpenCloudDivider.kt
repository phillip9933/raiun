package eu.opencloud.android.next.core.designsystem.component

import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.Dp
import eu.opencloud.android.next.core.designsystem.theme.LocalOpenCloudExtendedColors
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import androidx.compose.material3.HorizontalDivider as MaterialHorizontalDivider
import androidx.compose.material3.VerticalDivider as MaterialVerticalDivider

@Composable
fun HorizontalDivider(
    modifier: Modifier = Modifier,
    thickness: Dp = OpenCloudDimensions.DividerThickness,
    color: Color = LocalOpenCloudExtendedColors.current.border,
) {
    MaterialHorizontalDivider(modifier = modifier, thickness = thickness, color = color)
}

@Composable
fun VerticalDivider(
    modifier: Modifier = Modifier,
    thickness: Dp = OpenCloudDimensions.DividerThickness,
    color: Color = LocalOpenCloudExtendedColors.current.border,
) {
    MaterialVerticalDivider(modifier = modifier, thickness = thickness, color = color)
}
