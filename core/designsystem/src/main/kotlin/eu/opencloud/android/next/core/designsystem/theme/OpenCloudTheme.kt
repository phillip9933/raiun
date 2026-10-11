package eu.opencloud.android.next.core.designsystem.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

val OpenCloudLightColorScheme =
    lightColorScheme(
        primary = OpenCloudColor.Primary,
        onPrimary = OpenCloudColor.OnPrimary,
        primaryContainer = OpenCloudColor.PrimaryContainer,
        onPrimaryContainer = OpenCloudColor.OnPrimaryContainer,
        secondary = OpenCloudColor.Secondary,
        onSecondary = OpenCloudColor.OnSecondary,
        secondaryContainer = OpenCloudColor.SecondaryContainer,
        onSecondaryContainer = OpenCloudColor.OnSecondaryContainer,
        tertiary = OpenCloudColor.Tertiary,
        tertiaryContainer = OpenCloudColor.TertiaryContainer,
        background = OpenCloudColor.Background,
        onBackground = OpenCloudColor.OnBackground,
        surface = OpenCloudColor.Surface,
        onSurface = OpenCloudColor.OnSurface,
        surfaceVariant = OpenCloudColor.SurfaceVariant,
        onSurfaceVariant = OpenCloudColor.OnSurfaceVariant,
        surfaceContainer = OpenCloudColor.SurfaceContainer,
        surfaceContainerHigh = OpenCloudColor.SurfaceContainerHigh,
        surfaceContainerHighest = OpenCloudColor.SurfaceContainerHighest,
        surfaceContainerLow = OpenCloudColor.SurfaceContainerLow,
        surfaceDim = OpenCloudColor.SurfaceDim,
        outline = OpenCloudColor.Outline,
        outlineVariant = OpenCloudColor.OutlineVariant,
        error = OpenCloudColor.Error,
        onError = OpenCloudColor.OnError,
        errorContainer = OpenCloudColor.ErrorContainer,
        onErrorContainer = OpenCloudColor.OnErrorContainer,
        scrim = OpenCloudColor.Scrim,
    )

data class OpenCloudExtendedColors(
    val chrome: Color,
    val onChrome: Color,
)

val LocalOpenCloudExtendedColors =
    staticCompositionLocalOf {
        OpenCloudExtendedColors(
            chrome = OpenCloudColor.Chrome,
            onChrome = OpenCloudColor.OnChrome,
        )
    }

object OpenCloudDimensions {
    val DestinationPickerHeight = 320.dp
    val BackupExclusionsListHeight = 400.dp
    val VersionHistoryListHeight = 360.dp
    val DocumentPreviewHeight = 180.dp
    val WordmarkWidth = 170.dp
    val WordmarkHeight = 35.dp
    val ProfilePictureSize = 112.dp
    val CompactMenuRowHeight = 44.dp
    val PersonalIndicatorWidth = 74.dp
    val PersonalIndicatorHeight = 42.dp
    val PersonalCrownWidth = 80.dp
    val PersonalNavigationSize = 44.dp
    val PersonalNavigationIconSize = 34.dp
    val DrawerMaxWidth = 280.dp
    val Zero = 0.dp
    val SpacingXxs = 4.dp
    val SpacingXs = 8.dp
    val SpacingSm = 12.dp
    val SpacingMd = 16.dp
    val SpacingLg = 20.dp
    val SpacingXl = 24.dp
    val SpacingXxl = 32.dp

    val StrokeThin = 1.5.dp
    val StrokeRegular = 2.dp
    val StrokeEmphasis = 2.4.dp
    val StrokeCheckmark = 2.5.dp

    val CheckboxCornerRadius = 4.dp
    val ContentCornerRadius = 12.dp
    val FabCornerRadius = 28.dp

    val ViewHeaderHeight = 42.dp
    val CondensedRowHeight = 44.dp
    val TouchTarget = 48.dp
    val GlobalTopBarHeight = 52.dp
    val DefaultRowHeight = 56.dp
    val GridIconAreaHeight = 72.dp
    val ListNameIndent = 80.dp
    val ContentBottomClearance = 96.dp

    val CheckboxSize = 20.dp
    val IconMedium = 24.dp
    val BrandMarkWidth = 22.dp
    val BrandMarkSize = 28.dp
    val AvatarSize = 32.dp
    val TopBarActionSize = 36.dp
    val FabSize = 56.dp

    val ElevationNone = 0.dp
    val ElevationMedium = 6.dp
}

private val OpenCloudTypography =
    androidx.compose.material3.Typography(
        headlineSmall =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.SemiBold,
                fontSize = 20.sp,
                lineHeight = 26.sp,
            ),
        titleMedium =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontWeight = FontWeight.SemiBold,
                fontSize = 16.sp,
                lineHeight = 22.sp,
            ),
        bodyLarge =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontSize = 16.sp,
                lineHeight = 24.sp,
            ),
        bodyMedium =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontSize = 14.sp,
                lineHeight = 20.sp,
            ),
        bodySmall =
            TextStyle(
                fontFamily = FontFamily.SansSerif,
                fontSize = 12.sp,
                lineHeight = 16.sp,
            ),
    )

@Composable
@Suppress("FunctionNaming", "ktlint:standard:function-naming")
fun OpenCloudTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit,
) {
    val colors =
        if (darkTheme) {
            darkColorScheme(
                primary = Color(0xFF8AD3E3),
                onPrimary = Color(0xFF003640),
                primaryContainer = Color(0xFF004E5D),
                onPrimaryContainer = Color(0xFFB0ECFA),
                secondary = Color(0xFFB1CBD0),
                secondaryContainer = Color(0xFF324B50),
                background = Color(0xFF101416),
                surface = Color(0xFF101416),
                surfaceContainer = Color(0xFF1C2022),
                onSurface = Color(0xFFE0E3E5),
            )
        } else {
            OpenCloudLightColorScheme
        }
    androidx.compose.runtime.CompositionLocalProvider(
        LocalOpenCloudExtendedColors provides
            OpenCloudExtendedColors(
                chrome = if (darkTheme) colors.surface else OpenCloudColor.Chrome,
                onChrome = if (darkTheme) colors.onSurface else OpenCloudColor.OnChrome,
            ),
    ) {
        MaterialTheme(
            colorScheme = colors,
            typography = OpenCloudTypography,
            content = content,
        )
    }
}
