package eu.opencloud.android.next.core.designsystem.theme

import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.graphics.toArgb
import org.junit.Assert.assertEquals
import org.junit.Test

class OpenCloudColorTest {
    @Test
    fun `primary matches the extracted web token`() {
        assertEquals(0xFF00677F.toInt(), OpenCloudColor.Primary.toArgb())
    }

    @Test
    fun `surface container matches the extracted web token`() {
        assertEquals(0xFFF6F8FA.toInt(), OpenCloudColor.SurfaceContainer.toArgb())
    }
}

class OpenCloudSemanticContrastTest {
    @Test
    fun `text and status colors remain readable across primary surfaces`() {
        listOf(
            OpenCloudLightColorScheme to OpenCloudLightExtendedColors,
            OpenCloudDarkColorScheme to OpenCloudDarkExtendedColors,
        ).forEach { (scheme, extended) ->
            listOf(scheme.background, scheme.surface, scheme.surfaceVariant).forEach { surface ->
                listOf(
                    scheme.onSurface,
                    scheme.onSurfaceVariant,
                    scheme.error,
                    extended.success,
                    extended.warning,
                    extended.info,
                ).forEach { foreground ->
                    org.junit.Assert.assertTrue("$foreground on $surface", contrast(foreground, surface) >= 4.5)
                }
                org.junit.Assert.assertTrue("primary on $surface", contrast(scheme.primary, surface) >= 4.5)
            }
        }
    }

    @Test
    fun `control outlines contrast with neutral surfaces`() {
        listOf(OpenCloudLightColorScheme, OpenCloudDarkColorScheme).forEach { scheme ->
            listOf(
                scheme.background,
                scheme.surface,
                scheme.surfaceVariant,
                scheme.surfaceBright,
                scheme.surfaceDim,
                scheme.surfaceContainerLowest,
                scheme.surfaceContainerLow,
                scheme.surfaceContainer,
                scheme.surfaceContainerHigh,
                scheme.surfaceContainerHighest,
            ).forEach { surface ->
                listOf(scheme.outline, scheme.outlineVariant).forEach { outline ->
                    org.junit.Assert.assertTrue("$outline on $surface", contrast(outline, surface) >= 3.0)
                }
            }
        }
    }

    @Test
    fun `account identity accents retain readable foregrounds`() {
        AccountAccent.palette.forEach { accent ->
            org.junit.Assert.assertTrue("Account label contrast", contrast(AccountAccent.onAccent, accent) >= 4.5)
        }
    }

    @Test
    fun `account markers and soft selected cards stay readable across themes`() {
        listOf(false, true).forEach { dark ->
            val scheme = if (dark) OpenCloudDarkColorScheme else OpenCloudLightColorScheme
            eu.opencloud.android.next.core.model.AccountColor.entries.forEach { choice ->
                val indicator = AccountAccent.indicator("contrast-account", dark, choice)
                org.junit.Assert.assertTrue(
                    "$choice avatar ring",
                    contrast(indicator, scheme.surfaceContainerHighest) >= 3.0,
                )
                val tint = AccountAccent.container(scheme.surface, "contrast-account", dark, choice)
                org.junit.Assert.assertTrue("$choice account label", contrast(scheme.onSurface, tint) >= 4.5)
                org.junit.Assert.assertTrue("$choice account details", contrast(scheme.onSurfaceVariant, tint) >= 4.5)
            }
        }
    }

    private fun contrast(
        foreground: androidx.compose.ui.graphics.Color,
        background: androidx.compose.ui.graphics.Color,
    ): Double {
        val a = foreground.luminance().toDouble()
        val b = background.luminance().toDouble()
        return (maxOf(a, b) + 0.05) / (minOf(a, b) + 0.05)
    }
}
