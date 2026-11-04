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

// Native mappings of the frozen shared design draft v1. Material components retain
// their platform behavior; role values are explicit in both themes.
val OpenCloudLightColorScheme =
    lightColorScheme(
        primary = Color(0xFF00677F),
        onPrimary = Color.White,
        primaryContainer = Color(0xFFB7EAFF),
        onPrimaryContainer = Color(0xFF001F28),
        inversePrimary = Color(0xFF83D1E5),
        secondary = Color(0xFF20434F),
        onSecondary = Color.White,
        secondaryContainer = Color(0xFFCFE6F1),
        onSecondaryContainer = Color(0xFF071E26),
        tertiary = Color(0xFF005C73),
        onTertiary = Color.White,
        tertiaryContainer = Color(0xFFC5E8F2),
        onTertiaryContainer = Color(0xFF00212A),
        background = Color(0xFFF6F8FA),
        onBackground = Color(0xFF192B32),
        surface = Color.White,
        onSurface = Color(0xFF192B32),
        surfaceVariant = Color(0xFFF1F4F6),
        onSurfaceVariant = Color(0xFF52636D),
        surfaceTint = Color(0xFF00677F),
        surfaceBright = Color.White,
        surfaceDim = Color(0xFFE2E8EB),
        surfaceContainerLowest = Color.White,
        surfaceContainerLow = Color(0xFFFAFBFC),
        surfaceContainer = Color(0xFFF6F8FA),
        surfaceContainerHigh = Color(0xFFF1F4F6),
        surfaceContainerHighest = Color(0xFFE9EEF0),
        inverseSurface = Color(0xFF192327),
        inverseOnSurface = Color(0xFFEDF3F6),
        outline = Color(0xFF71828B),
        outlineVariant = Color(0xFF71828B),
        error = Color(0xFFA22E35),
        onError = Color.White,
        errorContainer = Color(0xFFFFDAD6),
        onErrorContainer = Color(0xFF410002),
        scrim = Color.Black,
    )

val OpenCloudDarkColorScheme =
    darkColorScheme(
        primary = Color(0xFF83D1E5),
        onPrimary = Color(0xFF003543),
        primaryContainer = Color(0xFF004E5D),
        onPrimaryContainer = Color(0xFFB0ECFA),
        inversePrimary = Color(0xFF00677F),
        secondary = Color(0xFFB1CBD0),
        onSecondary = Color(0xFF1B343A),
        secondaryContainer = Color(0xFF324B50),
        onSecondaryContainer = Color(0xFFCDE7EC),
        tertiary = Color(0xFF8CD6ED),
        onTertiary = Color(0xFF003543),
        tertiaryContainer = Color(0xFF004D60),
        onTertiaryContainer = Color(0xFFC5E8F2),
        background = Color(0xFF11181C),
        onBackground = Color(0xFFEDF3F6),
        surface = Color(0xFF192327),
        onSurface = Color(0xFFEDF3F6),
        surfaceVariant = Color(0xFF212D32),
        onSurfaceVariant = Color(0xFFADBEC6),
        surfaceTint = Color(0xFF83D1E5),
        surfaceBright = Color(0xFF34464E),
        surfaceDim = Color(0xFF11181C),
        surfaceContainerLowest = Color(0xFF11181C),
        surfaceContainerLow = Color(0xFF151E22),
        surfaceContainer = Color(0xFF192327),
        surfaceContainerHigh = Color(0xFF212D32),
        surfaceContainerHighest = Color(0xFF293A40),
        inverseSurface = Color(0xFFEDF3F6),
        inverseOnSurface = Color(0xFF192B32),
        outline = Color(0xFF8CA1AB),
        outlineVariant = Color(0xFF8CA1AB),
        error = Color(0xFFFFB4AB),
        onError = Color(0xFF690005),
        errorContainer = Color(0xFF93000A),
        onErrorContainer = Color(0xFFFFDAD6),
        scrim = Color.Black,
    )

data class OpenCloudExtendedColors(
    val chrome: Color,
    val onChrome: Color,
    val success: Color,
    val warning: Color,
    val info: Color,
    val border: Color,
)

val OpenCloudLightExtendedColors =
    OpenCloudExtendedColors(
        chrome = OpenCloudColor.Chrome,
        onChrome = OpenCloudColor.OnChrome,
        success = Color(0xFF22664F),
        warning = Color(0xFF805100),
        info = Color(0xFF005C73),
        border = Color(0xFFDCE3E7),
    )

val OpenCloudDarkExtendedColors =
    OpenCloudExtendedColors(
        chrome = OpenCloudDarkColorScheme.surface,
        onChrome = OpenCloudDarkColorScheme.onSurface,
        success = Color(0xFF8ED4B1),
        warning = Color(0xFFF0C37C),
        info = Color(0xFF8CD6ED),
        border = Color(0xFF34464E),
    )

val LocalOpenCloudExtendedColors = staticCompositionLocalOf { OpenCloudLightExtendedColors }

object OpenCloudDimensions {
    val SettingsChoiceMaxWidth = 200.dp
    val DestinationPickerHeight = 320.dp
    val PageNavigationMinInlineWidth = 320.dp
    val TransferDateRangePickerHeight = 500.dp
    val BackupExclusionsListHeight = 400.dp
    val VersionHistoryListHeight = 360.dp
    val DocumentPreviewHeight = 180.dp
    val WordmarkWidth = 170.dp
    val WordmarkHeight = 35.dp
    val ProfilePictureSize = 112.dp
    val CompactMenuRowHeight = 44.dp
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
    val DividerThickness = 1.dp
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
    val colors = if (darkTheme) OpenCloudDarkColorScheme else OpenCloudLightColorScheme
    androidx.compose.runtime.CompositionLocalProvider(
        LocalOpenCloudExtendedColors provides
            if (darkTheme) OpenCloudDarkExtendedColors else OpenCloudLightExtendedColors,
    ) {
        MaterialTheme(
            colorScheme = colors,
            typography = OpenCloudTypography,
            content = content,
        )
    }
}
