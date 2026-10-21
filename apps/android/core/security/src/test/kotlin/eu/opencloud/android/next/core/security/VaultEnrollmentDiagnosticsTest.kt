package eu.opencloud.android.next.core.security

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import javax.crypto.BadPaddingException
import javax.crypto.IllegalBlockSizeException

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VaultEnrollmentDiagnosticsTest {
    @Test
    fun nestedAuthenticationFailureHasSafeStageWithoutRawCause() {
        val providerText = "private provider detail"
        val error =
            IllegalBlockSizeException(providerText).apply {
                initCause(UserNotAuthenticatedException(providerText))
            }

        val result = classifyEnrollmentCryptoFailure(error)

        assertEquals(VaultEnrollmentFailure.AUTHORIZATION, result.failure)
        assertEquals(VaultEnrollmentCryptoCause.ILLEGAL_BLOCK_SIZE, result.cryptoCause)
        assertNull(result.cause)
        assertFalse(result.message.orEmpty().contains(providerText))
    }

    @Test
    fun nestedInvalidatedKeyAndBadPaddingAreClassified() {
        val error =
            BadPaddingException("private provider detail").apply {
                initCause(KeyPermanentlyInvalidatedException("private provider detail"))
            }

        val result = classifyEnrollmentCryptoFailure(error)

        assertEquals(VaultEnrollmentFailure.KEY_INVALIDATED, result.failure)
        assertEquals(VaultEnrollmentCryptoCause.BAD_PADDING, result.cryptoCause)
        assertNull(result.cause)
    }

    @Test
    fun publicKeystoreCodeIsRetainedOnApi35WithoutProviderText() {
        val providerText = "private provider detail"
        val result = classifyEnrollmentCryptoFailure(keystoreError(providerText))

        assertEquals(VaultEnrollmentFailure.CRYPTO_FINALIZATION, result.failure)
        assertEquals(android.security.KeyStoreException.ERROR_USER_AUTHENTICATION_REQUIRED, result.keyStoreErrorCode)
        assertNull(result.cause)
        assertFalse(result.message.orEmpty().contains(providerText))
    }

    @Test
    @Config(sdk = [26])
    fun publicKeystoreCodeIsAbsentBeforeApi33() {
        val result = classifyEnrollmentCryptoFailure(keystoreError("private provider detail"))

        assertNull(result.keyStoreErrorCode)
        assertNull(result.cause)
    }

    /** Android's platform exception constructor is hidden from application compile stubs. */
    private fun keystoreError(message: String): Throwable {
        val type = Class.forName("android.security.KeyStoreException")
        val constructor = type.getDeclaredConstructor(Int::class.javaPrimitiveType, String::class.java)
        constructor.isAccessible = true
        return constructor.newInstance(-26, message) as Throwable
    }
}
