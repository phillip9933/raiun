package eu.opencloud.android.next.ui

/** One automatic attempt per entered location. Cancellation leaves the password/manual button usable. */
internal class VaultAutomaticBiometricPrompt {
    private var consumed = false

    fun consumeIfReady(
        state: VaultRouteState,
        resumed: Boolean,
    ): Boolean {
        // An explicit relock after viewing content must not immediately reopen the fingerprint prompt.
        if (state.mode == VaultRouteMode.CONTENTS) consumed = true
        val ready = state.mode == VaultRouteMode.UNLOCK && !state.loading && state.error == null
        val usableEnrollment = state.biometricEnrolled && !state.biometricNeedsForget
        val eligible = resumed && ready && usableEnrollment
        if (consumed || !eligible) {
            return false
        }
        consumed = true
        return true
    }
}
