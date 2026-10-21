package eu.opencloud.android.next

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.PasswordCharacterClass
import eu.opencloud.android.next.core.network.ShareRejection
import eu.opencloud.android.next.core.network.safeMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import eu.opencloud.android.next.feature.files.R as FilesR

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "de-rDE")
class GermanLocaleResourceTest {
    @Test fun fileCountsUseGermanSingularAndPlural() {
        val resources = RuntimeEnvironment.getApplication().resources
        assertEquals("1 Datei", resources.getQuantityString(FilesR.plurals.browser_file_count, 1, 1))
        assertEquals("2 Dateien", resources.getQuantityString(FilesR.plurals.browser_file_count, 2, 2))
        assertEquals("1 Ordner", resources.getQuantityString(FilesR.plurals.browser_folder_count, 1, 1))
        assertEquals("2 Ordner", resources.getQuantityString(FilesR.plurals.browser_folder_count, 2, 2))
    }

    @Test fun typedErrorsResolveGermanAndFormatStatusAndPolicyValues() {
        val context = RuntimeEnvironment.getApplication()
        val connectivity = OpenCloudError.Connectivity
        assertNotEquals(connectivity.safeMessage(), connectivity.safeMessage(context))
        val http = OpenCloudError.HttpFailure(507).safeMessage(context)
        assertTrue(http.contains("507"))
        assertFalse(http.contains("%1"))
        val policy =
            OpenCloudError
                .ShareRejected(
                    ShareRejection.PASSWORD_POLICY,
                    linkedMapOf(PasswordCharacterClass.LENGTH to 12, PasswordCharacterClass.SPECIAL to 1),
                ).safeMessage(context)
        assertNotEquals(OpenCloudError.ShareRejected(ShareRejection.PASSWORD_POLICY).safeMessage(), policy)
        assertTrue(policy.contains("12"))
        assertTrue(policy.contains("; "))
        assertFalse(policy.contains("%1"))
    }
}
