package eu.opencloud.android.next

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "de-rDE")
class ScannerGermanResourcesTest {
    @Test
    @Config(qualifiers = "en")
    fun scannerEnglishDefaultsRemainAvailableFromLibrary() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals("Take photo", context.getString(dev.offlinescan.ui.R.string.action_shutter))
        assertEquals(
            "This page may look soft. Check it and retake if needed.",
            context.getString(dev.offlinescan.ui.R.string.capture_quality_hint),
        )
        assertEquals(
            "2 of 5 pages",
            context.resources.getQuantityString(dev.offlinescan.ui.R.plurals.save_page_position, 5, 2, 5),
        )
    }

    @Test fun scannerLibraryUsesGermanHostResourcesAndKeepsFormatArguments() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals("Foto aufnehmen", context.getString(dev.offlinescan.ui.R.string.action_shutter))
        assertEquals("Seite 2 von 5", context.getString(dev.offlinescan.ui.R.string.review_page_position, 2, 5))
        assertEquals("Speicherort", context.getString(dev.offlinescan.ui.R.string.save_location_label))
        assertEquals(
            "Diese Seite könnte unscharf sein. Prüfe sie und nimm sie bei Bedarf erneut auf.",
            context.getString(dev.offlinescan.ui.R.string.capture_quality_hint),
        )
        assertEquals(
            "Original: 4032 × 3024 Pixel",
            context.getString(dev.offlinescan.ui.R.string.review_original_dimensions, 4032, 3024),
        )
        assertEquals(
            "2 von 5 Seiten",
            context.resources.getQuantityString(dev.offlinescan.ui.R.plurals.save_page_position, 5, 2, 5),
        )
    }

    @Test
    @Config(qualifiers = "fr")
    fun scannerFrenchOverlay() = assertOverlay("Prendre une photo", "2 sur 5 pages")

    @Test
    @Config(qualifiers = "es")
    fun scannerSpanishOverlay() = assertOverlay("Tomar foto", "2 de 5 páginas")

    @Test
    @Config(qualifiers = "pt-rPT")
    fun scannerPortugueseOverlay() = assertOverlay("Tirar fotografia", "2 de 5 páginas")

    @Test
    @Config(qualifiers = "ja")
    fun scannerJapaneseOverlay() = assertOverlay("写真を撮影", "5ページ中2ページ")

    private fun assertOverlay(
        shutter: String,
        pages: String,
    ) {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals(shutter, context.getString(dev.offlinescan.ui.R.string.action_shutter))
        assertEquals(
            pages,
            context.resources.getQuantityString(dev.offlinescan.ui.R.plurals.save_page_position, 5, 2, 5),
        )
    }
}
