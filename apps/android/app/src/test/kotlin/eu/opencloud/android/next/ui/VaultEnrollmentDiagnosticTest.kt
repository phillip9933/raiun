package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.security.VaultEnrollmentCryptoCause
import eu.opencloud.android.next.core.security.VaultEnrollmentException
import eu.opencloud.android.next.core.security.VaultEnrollmentFailure
import org.junit.Assert.assertEquals
import org.junit.Test

class VaultEnrollmentDiagnosticTest {
    @Test fun onlyKnownFieldsAreShown() {
        val failure =
            VaultEnrollmentException(
                VaultEnrollmentFailure.CRYPTO_FINALIZATION,
                VaultEnrollmentCryptoCause.ILLEGAL_BLOCK_SIZE,
                15,
            )
        assertEquals("CRYPTO_FINALIZATION / ILLEGAL_BLOCK_SIZE / KS15", enrollmentDiagnostic(failure))
        assertEquals("ENROLLMENT_UNKNOWN", enrollmentDiagnostic(IllegalStateException("synthetic-private-detail")))
        assertEquals(
            "PERSISTENCE",
            enrollmentDiagnostic(VaultEnrollmentException(VaultEnrollmentFailure.PERSISTENCE, keyStoreErrorCode = 999)),
        )
    }
}
