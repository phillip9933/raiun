package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.security.VaultEnrollmentException

/** Only fixed categories and bounded Android public codes; never provider messages, keys or paths. */
internal fun enrollmentDiagnostic(failure: Exception): String {
    val error = failure as? VaultEnrollmentException ?: return "ENROLLMENT_UNKNOWN"
    return buildList {
        add(error.failure.name)
        error.cryptoCause?.let { add(it.name) }
        error.keyStoreErrorCode?.takeIf { it in 0..255 }?.let { add("KS$it") }
    }.joinToString(" / ")
}
