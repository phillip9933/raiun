package eu.opencloud.android.next.ui

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.security.VaultDeviceRememberOutcomeUnknownException
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.security.VaultRememberChoice
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import javax.crypto.Cipher
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultSessionLifecycleTest {
    @After fun resetMain() {
        Dispatchers.resetMain()
    }

    @Test fun cancellingPostOpenRetainsAdoptedCredentialsUntilTheSessionCloses() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val fixture = Fixture(this)
            var pendingPostOpen: Continuation<Unit>? = null
            fixture.afterOpen = { suspendCoroutine { pendingPostOpen = it } }
            fixture.enter()
            val password = "synthetic".toCharArray()
            fixture.lifecycle.unlock(password)
            runCurrent()
            assertEquals(VaultRouteMode.CONTENTS, fixture.state.value.mode)
            assertSame(fixture.opened, fixture.lifecycle.session)
            assertNotNull(pendingPostOpen)

            fixture.lifecycle.nextGeneration()
            requireNotNull(pendingPostOpen).resume(Unit)
            advanceUntilIdle()

            assertFalse(fixture.sessionClosed)
            assertFalse(fixture.snapshotClosed)
            assertTrue(fixture.material.any { it != 0.toByte() })
            assertTrue(password.all { it == '\u0000' })
            assertNotNull(fixture.lifecycle.prepareBiometricEnrollment())

            fixture.events.clear()
            fixture.lifecycle.onDeviceLocked()

            assertTrue(fixture.snapshotClosed)
            assertTrue(fixture.sessionClosed)
            assertTrue(fixture.material.all { it == 0.toByte() })
            assertEquals(listOf("directory", "leases", "session"), fixture.events.take(3))
            fixture.lifecycle.leave()
        }

    @Test fun changingGenerationRejectsBothOldBiometricCompletionsForTheSameTarget() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val fixture = Fixture(this)
            fixture.enter()
            val oldUnlock = fixture.lifecycle.prepareBiometricUnlock()
            assertNotNull(oldUnlock)
            fixture.lifecycle.nextGeneration()
            fixture.lifecycle.completeBiometricUnlock(oldUnlock)
            assertEquals(1, fixture.biometrics.cancelledUnlocks)
            assertEquals(0, fixture.biometrics.completedUnlocks)

            fixture.lifecycle.unlock("synthetic".toCharArray())
            advanceUntilIdle()
            val oldEnrollment = fixture.lifecycle.prepareBiometricEnrollment()
            assertNotNull(oldEnrollment)
            fixture.lifecycle.nextGeneration()
            fixture.lifecycle.completeBiometricEnrollment(oldEnrollment)

            assertEquals(1, fixture.biometrics.cancelledEnrollments)
            assertEquals(0, fixture.biometrics.completedEnrollments)
            assertTrue(fixture.material.all { it == 0.toByte() })
            assertSame(fixture.opened, fixture.lifecycle.session)
            fixture.lifecycle.leave()
        }

    @Test fun targetAdmissionRejectsInactiveRoutesAndAnotherAccount() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val fixture = Fixture(this)
            val location = VaultViewModelRaceTest.location
            val selected = VaultSessionTarget(location, location.vaultPath, location.title, location.remoteVaultId)
            assertTrue(
                runCatching { fixture.lifecycle.replaceTarget(selected) }.exceptionOrNull() is IllegalStateException,
            )
            assertEquals(null, fixture.lifecycle.target)

            fixture.enter()
            val anotherAccount = selected.copy(location = location.copy(accountId = "another-synthetic-account"))
            assertTrue(
                runCatching {
                    fixture.lifecycle.selectTarget(
                        anotherAccount,
                    )
                }.exceptionOrNull() is IllegalStateException,
            )
            assertEquals(selected, fixture.lifecycle.target)
            fixture.lifecycle.leave()
        }

    @Test fun unknownRememberOutcomeCannotWipeAFreshSessionForTheSameIdentity() {
        assertUnknownOutcomePreservesReplacement(sameIdentity = true)
    }

    @Test fun unknownRememberOutcomeCannotWipeAFreshSessionForAnotherIdentity() {
        assertUnknownOutcomePreservesReplacement(sameIdentity = false)
    }

    private fun assertUnknownOutcomePreservesReplacement(sameIdentity: Boolean) {
        // A dispatching inline dispatcher permits a controlled replacement while provider IO is in progress.
        val dispatcher =
            object : CoroutineDispatcher() {
                override fun dispatch(
                    context: CoroutineContext,
                    block: Runnable,
                ) = block.run()
            }
        Dispatchers.setMain(dispatcher)
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
        val remember = UnknownRemember()
        val fixture = Fixture(scope, remember)
        val oldIdentity = VaultViewModelRaceTest.identity
        val location =
            VaultViewModelRaceTest.location.let {
                if (sameIdentity) it else it.copy(remoteVaultId = "replacement-vault")
            }
        val replacementMaterial = ByteArray(80) { 9 }
        var replacementClosed = false
        val replacement =
            object : VaultRouteSession by VaultViewModelRaceTest.TestSession(
                oldIdentity.copy(remoteVaultId = location.remoteVaultId),
                emptyList(),
            ) {
                override suspend fun exportVerifiedKeyMaterial() = replacementMaterial

                override fun close() {
                    replacementClosed = true
                }
            }
        try {
            fixture.enter()
            fixture.lifecycle.unlock("first-synthetic".toCharArray())
            assertTrue(fixture.state.value.phoneRememberOffer)
            remember.beforeUnknownOutcome = {
                fixture.lifecycle.leave()
                fixture.nextOpened = replacement
                fixture.enter(location)
                fixture.lifecycle.unlock("replacement-synthetic".toCharArray())
                assertSame(replacement, fixture.lifecycle.session)
                assertTrue(fixture.state.value.phoneRememberOffer)
            }

            fixture.lifecycle.rememberOnPhone()

            assertEquals(false, runBlocking { VaultDeviceRememberRevocations.await(oldIdentity) })
            assertSame(replacement, fixture.lifecycle.session)
            assertFalse(replacementClosed)
            assertTrue(fixture.state.value.phoneRememberOffer)
            assertEquals(null, fixture.state.value.error)
            assertTrue(replacementMaterial.any { it != 0.toByte() })
            assertNotNull(fixture.lifecycle.prepareBiometricEnrollment())
            fixture.lifecycle.leave()
            assertTrue(replacementMaterial.all { it == 0.toByte() })
            assertTrue(replacementClosed)

            // The old identity stays fenced even when its replacement used the same identity.
            // A later restore must durably retry forget before it can consider remembered access.
            remember.forgetFails = false
            fixture.enter()
            fixture.lifecycle.showPasswordUnlock(requireNotNull(fixture.lifecycle.target))
            assertEquals(null, runBlocking { VaultDeviceRememberRevocations.await(oldIdentity) })
            assertEquals(2, remember.forgetCalls)
            fixture.lifecycle.leave()
        } finally {
            fixture.lifecycle.leave()
            remember.forgetFails = false
            try {
                fixture.enter()
                fixture.lifecycle.showPasswordUnlock(requireNotNull(fixture.lifecycle.target))
            } finally {
                fixture.lifecycle.leave()
                scope.cancel()
            }
        }
    }

    private class Fixture(
        scope: CoroutineScope,
        remember: VaultDeviceRememberAccess = UnsupportedRemember,
    ) {
        val state = MutableStateFlow(VaultRouteState())
        val material = ByteArray(80) { 7 }
        val events = mutableListOf<String>()
        val biometrics = Biometrics()
        var sessionClosed = false
        var snapshotClosed = false
        var afterOpen: suspend () -> Unit = {}
        private val location = VaultViewModelRaceTest.location
        private val identity = VaultViewModelRaceTest.identity
        private val snapshot =
            object : VaultRouteDirectorySnapshot {
                override val totalCount = 0L

                override suspend fun page(
                    offset: Long,
                    limit: Int,
                ): List<VaultFolder> = emptyList()

                override fun close() {
                    if (!snapshotClosed) events += "directory"
                    snapshotClosed = true
                }
            }
        val opened =
            object : VaultRouteSession by VaultViewModelRaceTest.TestSession(identity, emptyList()) {
                override suspend fun exportVerifiedKeyMaterial() = material

                override suspend fun openDirectory(
                    path: String,
                    showHidden: Boolean,
                    excludedPath: String?,
                ): VaultRouteDirectorySnapshot = snapshot

                override fun close() {
                    if (!sessionClosed) events += "session"
                    sessionClosed = true
                }
            }
        var nextOpened: VaultRouteSession = opened
        private val repository =
            object : VaultRouteRepository by VaultViewModelRaceTest.TestRepository(unlockBlock = {
                _,
                _,
                _,
                _,
                ->
                nextOpened
            }) {
                override suspend fun unlockAccountSnapshot(accountId: String): Any = "synthetic-account-row"

                override suspend fun rememberBinding(accountId: String) =
                    VaultRememberBinding(
                        "0123456789abcdef0123456789abcdef",
                        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    )

                override fun unlockCredentialPermit(accountId: String): () -> Boolean = { true }
            }
        private val directory =
            VaultDirectoryContent(
                state,
                object : VaultDirectoryOwner {
                    override fun showHidden() = false

                    override fun isCurrent(
                        opened: VaultRouteSession,
                        token: Long,
                        account: String,
                    ) = lifecycle.isCurrent(token, account) && lifecycle.session === opened

                    override fun isRouteCurrent(
                        token: Long,
                        account: String,
                    ) = lifecycle.isCurrent(token, account)

                    override fun present(entries: List<VaultFolder>): List<VaultRouteEntry> = emptyList()

                    override fun clearPresented() = Unit

                    override fun reportFailure(
                        failure: Exception,
                        token: Long,
                        account: String,
                    ): Unit = throw AssertionError(failure)
                },
            )
        val lifecycle: VaultSessionLifecycle =
            VaultSessionLifecycle(
                ApplicationProvider.getApplicationContext<Application>(),
                repository,
                biometrics,
                Preferences,
                Dispatchers.Main,
                remember,
                scope,
                state,
                directory,
                object : VaultSessionPresentation {
                    override fun invalidateRoutePresentation() = Unit

                    override fun closeSessionContent() {
                        directory.close()
                        events += "leases"
                    }

                    override fun clearSensitivePresentation() = Unit

                    override fun clearPreview() = Unit

                    override fun presentLocation(location: VaultLocation) =
                        VaultRouteLocation("synthetic", location.title, VaultLocationKindUi.FOLDER_VAULT, true)

                    override fun presentEntries(entries: List<VaultFolder>): List<VaultRouteEntry> = emptyList()

                    override fun offersResolved() = Unit

                    override suspend fun postOpen(
                        opened: VaultRouteSession,
                        token: Long,
                        account: String,
                    ) = afterOpen()

                    override fun reportFailure(
                        failure: Throwable,
                        fallback: VaultRouteError,
                        context: VaultFailureContext,
                    ): Unit = throw AssertionError(failure)
                },
            )

        fun enter(location: VaultLocation = this.location) {
            lifecycle.enter(location.accountId)
            lifecycle.replaceTarget(
                VaultSessionTarget(location, location.vaultPath, location.title, location.remoteVaultId),
            )
        }
    }

    private class Biometrics : VaultBiometricKeyStore {
        var cancelledUnlocks = 0
        var completedUnlocks = 0
        var cancelledEnrollments = 0
        var completedEnrollments = 0

        override fun hasEnrollment(identity: VaultIdentity) = false

        override fun prepareEnrollment(identity: VaultIdentity): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

        override fun completeEnrollment(
            identity: VaultIdentity,
            cipher: Cipher,
            keyMaterial: ByteArray,
        ) {
            completedEnrollments += 1
        }

        override fun cancelEnrollment(identity: VaultIdentity) {
            cancelledEnrollments += 1
        }

        override fun prepareUnlock(identity: VaultIdentity): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

        override fun completeUnlock(
            identity: VaultIdentity,
            cipher: Cipher,
        ): ByteArray {
            completedUnlocks += 1
            return ByteArray(80) { 7 }
        }

        override fun cancelUnlock(identity: VaultIdentity) {
            cancelledUnlocks += 1
        }

        override fun forget(identity: VaultIdentity) = Unit
    }

    private class UnknownRemember : VaultDeviceRememberAccess by UnsupportedRemember {
        var beforeUnknownOutcome: () -> Unit = {}
        var forgetFails = true
        var forgetCalls = 0

        override fun isSupported() = true

        override fun begin(
            identity: VaultIdentity,
            binding: VaultRememberBinding,
        ): VaultDeviceRememberAccess.Admission = object : VaultDeviceRememberAccess.Admission {}

        override fun remember(
            admission: VaultDeviceRememberAccess.Admission?,
            identity: VaultIdentity,
            binding: VaultRememberBinding,
            verifiedKeyMaterial: ByteArray,
            permit: () -> Boolean,
        ): Boolean {
            check(permit())
            beforeUnknownOutcome()
            throw VaultDeviceRememberOutcomeUnknownException()
        }

        override fun forget(identity: VaultIdentity) {
            forgetCalls += 1
            if (forgetFails) error("Synthetic durable cleanup failure")
        }
    }

    private object Preferences : VaultOfferPreferences {
        override fun status(identity: VaultIdentity): VaultPreferenceStatus? = null

        override fun remember(
            identity: VaultIdentity,
            title: String,
            targetKind: VaultPreferenceTargetKind,
        ) = Unit

        override fun decline(
            identity: VaultIdentity,
            title: String,
            targetKind: VaultPreferenceTargetKind,
        ) = Unit

        override fun remove(identity: VaultIdentity) = Unit
    }

    private object UnsupportedRemember : VaultDeviceRememberAccess {
        override fun isSupported() = false

        override fun begin(
            identity: VaultIdentity,
            binding: VaultRememberBinding,
        ): VaultDeviceRememberAccess.Admission? = null

        override fun remember(
            admission: VaultDeviceRememberAccess.Admission?,
            identity: VaultIdentity,
            binding: VaultRememberBinding,
            verifiedKeyMaterial: ByteArray,
            permit: () -> Boolean,
        ) = false

        override fun restore(
            identity: VaultIdentity,
            binding: VaultRememberBinding,
            permit: () -> Boolean,
        ): VaultDeviceRememberKey? = null

        override fun choice(identity: VaultIdentity): VaultRememberChoice? = null

        override fun hasRemembered(identity: VaultIdentity) = false

        override fun decline(identity: VaultIdentity) = Unit

        override fun forget(identity: VaultIdentity) = Unit
    }
}
