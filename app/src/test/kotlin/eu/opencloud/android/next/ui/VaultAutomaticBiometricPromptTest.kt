package eu.opencloud.android.next.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultAutomaticBiometricPromptTest {
    private val enrolled = VaultRouteState(mode = VaultRouteMode.UNLOCK, biometricEnrolled = true)

    @Test fun cancellationAndRecompositionDoNotPromptAgain() {
        val prompt = VaultAutomaticBiometricPrompt()
        assertTrue(prompt.consumeIfReady(enrolled, resumed = true))
        assertFalse(prompt.consumeIfReady(enrolled, resumed = true))
        assertFalse(prompt.consumeIfReady(enrolled.copy(lockRevision = 2), resumed = true))
        assertTrue(VaultAutomaticBiometricPrompt().consumeIfReady(enrolled, resumed = true))
    }

    @Test fun waitsUntilResumedAndEnrollmentReady() {
        val prompt = VaultAutomaticBiometricPrompt()
        assertFalse(prompt.consumeIfReady(enrolled, resumed = false))
        assertFalse(prompt.consumeIfReady(enrolled.copy(loading = true), resumed = true))
        assertFalse(prompt.consumeIfReady(enrolled.copy(biometricEnrolled = false), resumed = true))
        assertFalse(prompt.consumeIfReady(enrolled.copy(biometricNeedsForget = true), resumed = true))
        assertFalse(prompt.consumeIfReady(enrolled.copy(error = VaultRouteError.BIOMETRIC), resumed = true))
        assertTrue(prompt.consumeIfReady(enrolled, resumed = true))
    }

    @Test fun relockingAfterPasswordEntryDoesNotImmediatelyUnlockAgain() {
        val prompt = VaultAutomaticBiometricPrompt()
        assertFalse(prompt.consumeIfReady(enrolled.copy(mode = VaultRouteMode.CONTENTS), resumed = true))
        assertFalse(prompt.consumeIfReady(enrolled, resumed = true))
    }
}
