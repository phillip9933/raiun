package eu.opencloud.android.next

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.PasswordCharacterClass
import eu.opencloud.android.next.core.network.ShareRejection
import eu.opencloud.android.next.core.network.safeMessage
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "en-rUS")
class OpenCloudErrorResourceTest {
    @Test fun passwordPolicyRetainsReadableRequirementsAndPunctuation() {
        val error =
            OpenCloudError.ShareRejected(
                ShareRejection.PASSWORD_POLICY,
                linkedMapOf(PasswordCharacterClass.LENGTH to 12, PasswordCharacterClass.SPECIAL to 1),
            )
        assertEquals(error.safeMessage(), error.safeMessage(RuntimeEnvironment.getApplication()))
        val generic = OpenCloudError.ShareRejected(ShareRejection.PASSWORD_POLICY)
        assertEquals(generic.safeMessage(), generic.safeMessage(RuntimeEnvironment.getApplication()))
    }

    @Test fun localizedHttpAndFileFailuresPreserveSafeEnglishContract() {
        val context = RuntimeEnvironment.getApplication()
        listOf(
            OpenCloudError.HttpFailure(400),
            OpenCloudError.ServerFailure(503, null),
            OpenCloudError.SourcePermissionDenied,
            OpenCloudError.PreconditionFailed,
            OpenCloudError.ShareRejected(ShareRejection.RESOURCE_REFERENCE),
        ).forEach { error -> assertEquals(error.safeMessage(), error.safeMessage(context)) }
    }
}
