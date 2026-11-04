package eu.opencloud.android.next.core.sync

import android.content.res.Configuration
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.safeMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.util.Locale

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class EncryptedOfflineCapacityMessageTest {
    @Test fun capacityMessageUsesLocalizedResourcesAndMatchesEnglishFallback() {
        val application = RuntimeEnvironment.getApplication()
        val error = OpenCloudError.EncryptedOfflineIndexFull
        val english = error.safeMessage()
        for (language in listOf("en", "de", "es", "fr", "ja", "pt-PT")) {
            val configuration = Configuration(application.resources.configuration)
            configuration.setLocale(Locale.forLanguageTag(language))
            val context = application.createConfigurationContext(configuration)
            val localized = error.safeMessage(context)
            if (language == "en") assertEquals(english, localized) else assertNotEquals(english, localized)
            assertNotEquals(OpenCloudError.Unknown.safeMessage(context), localized)
            assertNotEquals(OpenCloudError.LocalStorage.safeMessage(context), localized)
            assertNotEquals(OpenCloudError.QuotaExceeded.safeMessage(context), localized)
        }
    }
}
