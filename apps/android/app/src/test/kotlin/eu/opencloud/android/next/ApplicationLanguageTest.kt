package eu.opencloud.android.next

import android.app.LocaleManager
import android.os.Bundle
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
class ApplicationLanguageTest {
    @After fun resetLanguage() {
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList())
    }

    @Test
    @Config(sdk = [32], qualifiers = "en")
    fun explicitLanguagesSurviveNewActivitiesAndSystemClearsOverride() {
        val first = Robolectric.buildActivity(LanguageTestActivity::class.java).setup()
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("de"))
        shadowOf(Looper.getMainLooper()).idle()
        first.pause().stop().destroy()
        val german = Robolectric.buildActivity(LanguageTestActivity::class.java).setup()
        assertEquals(
            "Einstellungen",
            german.get().getString(eu.opencloud.android.next.feature.settings.R.string.settings_title),
        )
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags("en"))
        shadowOf(Looper.getMainLooper()).idle()
        german.pause().stop().destroy()
        val system = Robolectric.buildActivity(LanguageTestActivity::class.java).setup()
        assertEquals(
            "Settings",
            system.get().getString(eu.opencloud.android.next.feature.settings.R.string.settings_title),
        )
        AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList())
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals("", AppCompatDelegate.getApplicationLocales().toLanguageTags())
        system.pause().stop().destroy()
    }

    @Test
    @Config(sdk = [35])
    fun languageChoiceUsesAndroidPerAppPreferences() {
        val activity = Robolectric.buildActivity(LanguageTestActivity::class.java).setup()
        try {
            val manager = activity.get().getSystemService(LocaleManager::class.java)
            listOf("de", "fr", "es", "pt-PT", "ja", "en").forEach { tag ->
                AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(tag))
                assertEquals(tag, manager.applicationLocales.toLanguageTags())
            }
            AppCompatDelegate.setApplicationLocales(LocaleListCompat.getEmptyLocaleList())
            assertEquals("", manager.applicationLocales.toLanguageTags())
        } finally {
            activity.pause().stop().destroy()
        }
    }
}

class LanguageTestActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        applyStoredWindowTheme()
        super.onCreate(savedInstanceState)
    }
}
