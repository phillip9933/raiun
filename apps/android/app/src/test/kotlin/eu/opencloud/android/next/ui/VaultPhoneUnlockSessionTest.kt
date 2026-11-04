package eu.opencloud.android.next.ui

import android.app.Application
import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.VaultDeviceRememberOutcomeUnknownException
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.security.VaultRememberChoice
import eu.opencloud.android.next.core.security.VaultUnlockSession
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultUnlockException
import eu.opencloud.android.next.core.sync.VaultUnlockFailure
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultPhoneUnlockSessionTest {
    private val application: Application get() = ApplicationProvider.getApplicationContext()
    private val location = VaultViewModelRaceTest.location
    private val identity = VaultViewModelRaceTest.identity
    private lateinit var deviceRemember: FakeDeviceRemember

    @Before fun preparePhone() {
        deviceRemember = FakeDeviceRemember()
        seedAskEveryTimePreference(false)
        Shadows.shadowOf(application.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        Shadows.shadowOf(application.getSystemService(KeyguardManager::class.java)).setIsDeviceLocked(false)
        Shadows.shadowOf(application.getSystemService(PowerManager::class.java)).setIsInteractive(true)
    }

    @After fun cleanUp() {
        VaultUnlockSession(application).clear()
        seedAskEveryTimePreference(false)
        Dispatchers.resetMain()
    }

    private fun seedAskEveryTimePreference(value: Boolean) {
        check(
            application
                .getSharedPreferences("vault-unlock-policy", Context.MODE_PRIVATE)
                .edit()
                .putBoolean("ask-every-time", value)
                .commit(),
        )
    }

    @Test fun queuedOwnedMaterialIsWipedWhenCancelledBeforeDispatch() =
        runTest {
            val material = ByteArray(80) { 7 }
            var bodyStarted = false
            val job =
                launchWithOwnedMaterial(this, material) {
                    bodyStarted = true
                }

            job.cancel()
            runCurrent()

            assertFalse(bodyStarted)
            assertTrue(material.all { it == 0.toByte() })
        }

    @Test fun returningToOnlineOrOfflineLocationCreatesFreshProvenSessionWithoutAnotherExport() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            listOf(false, true).forEach { offline ->
                VaultUnlockSession(application).clear()
                deviceRemember = FakeDeviceRemember()
                val repository = PhoneRepository(offline)
                val model = model(repository)
                model.enterRoute(location.accountId, location.copy(offlineOnly = offline))
                advanceUntilIdle()
                model.unlock("password".toCharArray())
                advanceUntilIdle()
                assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
                assertEquals(1, repository.exports)
                model.rememberOnPhone()
                advanceUntilIdle()
                assertTrue(deviceRemember.hasRemembered(identity))
                assertTrue(requireNotNull(deviceRemember.lastReceivedMaterial).all { it == 0.toByte() })
                val first = repository.sessions.single()
                model.leaveRoute()
                assertTrue(first.closed)
                model.enterRoute(location.accountId, location.copy(offlineOnly = offline))
                val automaticPrompt = VaultAutomaticBiometricPrompt()
                assertTrue(model.state.value.loading)
                assertFalse(
                    automaticPrompt.consumeIfReady(model.state.value.copy(biometricEnrolled = true), resumed = true),
                )
                advanceUntilIdle()
                assertEquals(1, repository.passwordUnlocks)
                assertEquals(1, repository.keyUnlocks)
                assertEquals(1, repository.exports)
                assertEquals(2, repository.sessions.size)
                assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
                assertEquals(offline, model.state.value.offline)
                assertFalse(model.state.value.biometricOfferPending)
                assertFalse(model.state.value.canEnrollBiometric)
                assertTrue(repository.sessions.last().listCalls > 0)
                model.leaveRoute()
            }
        }

    @Test fun screenOffPreservesDurableConsentButExplicitVaultLockRevokesIt() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val model = model(repository)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            model.rememberOnPhone()
            advanceUntilIdle()
            model.onRouteStopped()
            assertTrue(repository.sessions.single().closed)
            model.onRouteStarted()
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals(null, model.state.value.phoneSessionIssueCode)
            model.onDeviceLocked()
            assertTrue(deviceRemember.hasRemembered(identity))
            deviceRemember.deviceAvailable = false
            model.onRouteStarted()
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertTrue(deviceRemember.hasRemembered(identity))
            deviceRemember.deviceAvailable = true
            model.onRouteStarted()
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertTrue(deviceRemember.restoreBindings.contains(repository.binding))
            var observedPendingLock = false
            deviceRemember.beforeForget = { observedPendingLock = model.state.value.lockingRememberedAccess }
            model.lock()
            advanceUntilIdle()
            assertTrue(observedPendingLock)
            assertFalse(deviceRemember.hasRemembered(identity))
            val restoresAfterExplicitLock = deviceRemember.restoreBindings.size
            model.onRouteStarted()
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertEquals(restoresAfterExplicitLock, deviceRemember.restoreBindings.size)
            model.leaveRoute()
        }

    @Test fun biometricAdmissionFailureShowsSafeCodeAndSuccessfulBiometricClearsOldCode() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository =
                PhoneRepository().apply {
                    beforeKey = { credentialGeneration++ }
                }
            deviceRemember.seedRemembered(identity, repository.binding)
            val model = model(repository, UnusedBiometrics(enrolled = true))
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.completeBiometricUnlock(model.prepareBiometricUnlock())
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals("US2", model.state.value.phoneSessionIssueCode)

            model.leaveRoute()
            repository.beforeKey = {}
            deviceRemember.restoreAvailable = false
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            model.completeBiometricUnlock(model.prepareBiometricUnlock())
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals(null, model.state.value.phoneSessionIssueCode)
            model.leaveRoute()
        }

    @Test fun rememberedKeyProofFailureShowsOpaqueCodeAndSuccessfulRetryClearsIt() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val model = model(repository, UnusedBiometrics(enrolled = true))
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.completeBiometricUnlock(model.prepareBiometricUnlock())
            advanceUntilIdle()
            model.rememberOnPhone()
            advanceUntilIdle()
            val keyUnlocksAfterFreshBiometricProof = repository.keyUnlocks
            model.leaveRoute()

            repository.proofFails = true
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertEquals("US7", model.state.value.phoneSessionIssueCode)
            assertEquals(keyUnlocksAfterFreshBiometricProof + 1, repository.keyUnlocks)
            model.leaveRoute()

            repository.proofFails = false
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals(null, model.state.value.phoneSessionIssueCode)
            assertEquals(keyUnlocksAfterFreshBiometricProof + 2, repository.keyUnlocks)
            model.leaveRoute()
        }

    @Test fun successfulBiometricProofSeedsPhoneSessionWithoutAnotherEnrollmentExport() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val biometrics = UnusedBiometrics(enrolled = true)
            val model = model(repository, biometrics)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.completeBiometricUnlock(model.prepareBiometricUnlock())
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            model.rememberOnPhone()
            advanceUntilIdle()
            assertEquals(0, repository.exports)
            assertEquals(1, biometrics.completions)
            assertTrue(requireNotNull(biometrics.deliveredMaterial).all { it == 0.toByte() })
            val first = repository.sessions.single()
            model.leaveRoute()
            assertTrue(first.closed)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals(2, repository.keyUnlocks)
            assertEquals(1, biometrics.completions)
            assertEquals(0, repository.exports)
            assertEquals(0, repository.passwordUnlocks)
            assertTrue(repository.sessions.last().listCalls > 0)
            assertFalse(model.state.value.biometricOfferPending)
            model.leaveRoute()
        }

    @Test fun durableConsentSurvivesNewViewModelAndRestoreUsesFreshRoomOwnerBinding() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val first = model(repository)
            first.enterRoute(location.accountId, location)
            advanceUntilIdle()
            first.unlock("password".toCharArray())
            advanceUntilIdle()
            first.rememberOnPhone()
            advanceUntilIdle()
            assertTrue(deviceRemember.hasRemembered(identity))
            first.leaveRoute()
            VaultUnlockSession(application).clear() // Model a process restart; the fake device record survives.

            val replacement = model(repository)
            replacement.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(listOf(repository.binding), deviceRemember.restoreBindings)
            assertEquals(1, repository.keyUnlocks)
            assertEquals(VaultRouteMode.CONTENTS, replacement.state.value.mode)
            replacement.leaveRoute()

            repository.binding =
                VaultRememberBinding(
                    "fedcba9876543210fedcba9876543210",
                    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                )
            val changedOwner = model(repository)
            changedOwner.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(repository.binding, deviceRemember.restoreBindings.last())
            assertEquals(VaultRouteMode.UNLOCK, changedOwner.state.value.mode)
            assertEquals(1, repository.keyUnlocks) // A Room owner ABA cannot inherit another binding's key.
            changedOwner.leaveRoute()
        }

    @Test fun declinePersistsAndAskEveryTimeSkipsDeviceRestore() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val first = model(repository)
            first.enterRoute(location.accountId, location)
            advanceUntilIdle()
            first.unlock("password".toCharArray())
            advanceUntilIdle()
            assertTrue(first.state.value.phoneRememberOffer)
            first.declineBiometricOffer()
            advanceUntilIdle()
            assertEquals(VaultRememberChoice.DECLINED, deviceRemember.choice(identity))
            first.leaveRoute()

            val declined = model(repository)
            declined.enterRoute(location.accountId, location)
            advanceUntilIdle()
            declined.unlock("password".toCharArray())
            advanceUntilIdle()
            assertFalse(declined.state.value.phoneRememberOffer)
            assertFalse(declined.state.value.biometricOfferPending)
            declined.leaveRoute()

            deviceRemember.seedRemembered(identity, repository.binding)
            VaultUnlockSession(application).clear()
            seedAskEveryTimePreference(true)
            val strict = model(repository)
            strict.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, strict.state.value.mode)
            assertTrue(deviceRemember.restoreBindings.isEmpty())
            strict.leaveRoute()
            seedAskEveryTimePreference(false)
        }

    @Test fun routeLockDuringEnrollmentCannotCommitThePendingExplicitChoice() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val model = model(repository)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            deviceRemember.beforeRemember = { model.lock() }
            model.rememberOnPhone()
            advanceUntilIdle()
            assertFalse(deviceRemember.hasRemembered(identity))
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertTrue(requireNotNull(deviceRemember.lastReceivedMaterial).all { it == 0.toByte() })
            model.leaveRoute()
        }

    @Test fun credentialPermitFromTheProvenSessionMustStillBeCurrentAtAcceptance() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val model = model(repository)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            repository.credentialGeneration++
            model.rememberOnPhone()
            advanceUntilIdle()
            assertFalse(deviceRemember.hasRemembered(identity))
            assertEquals(0, deviceRemember.beginCalls)
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertEquals(VaultRouteError.VAULT_CHANGED, model.state.value.error)
            assertFalse(model.state.value.phoneRememberOffer)
            model.leaveRoute()
        }

    @Test fun failedExplicitRevocationDoesNotReportLockCompleteOrTryRestore() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val model = model(repository)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            model.rememberOnPhone()
            advanceUntilIdle()
            deviceRemember.forgetFailure = true

            model.lock()
            advanceUntilIdle()

            assertFalse(model.state.value.lockingRememberedAccess)
            assertFalse(model.state.value.loading)
            assertFalse(model.state.value.allowAutomaticBiometric)
            assertEquals(VaultRouteError.PHONE_LOCK_FAILED, model.state.value.error)
            assertTrue(deviceRemember.hasRemembered(identity))
            model.onRouteStarted()
            advanceUntilIdle()
            assertTrue(deviceRemember.restoreBindings.isEmpty())
            assertEquals(VaultRouteError.PHONE_LOCK_FAILED, model.state.value.error)
            model.leaveRoute()
        }

    @Test fun replacementViewModelWaitsForAnInFlightExplicitForget() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val first = model(repository, ioDispatcher = Dispatchers.IO)
            first.enterRoute(location.accountId, location)
            advanceUntilIdle()
            first.unlock("password".toCharArray())
            advanceUntilIdle()
            first.rememberOnPhone()
            advanceUntilIdle()
            val forgetStarted = CountDownLatch(1)
            val releaseForget = CountDownLatch(1)
            val forgetReturned = CountDownLatch(1)
            deviceRemember.beforeForget = {
                forgetStarted.countDown()
                check(releaseForget.await(5, TimeUnit.SECONDS))
            }
            deviceRemember.afterForget = { forgetReturned.countDown() }

            first.lock()
            assertTrue(forgetStarted.await(5, TimeUnit.SECONDS))
            first.leaveRoute() // Route disposal must not cancel the durable revocation.
            val replacement = model(repository)
            replacement.enterRoute(location.accountId, location)
            runCurrent()
            assertTrue(replacement.state.value.loading)
            assertTrue(deviceRemember.restoreBindings.isEmpty())
            val completedFence = async { VaultDeviceRememberRevocations.await(identity) }
            runCurrent()

            releaseForget.countDown()
            assertTrue(forgetReturned.await(5, TimeUnit.SECONDS))
            assertEquals(true, completedFence.await())
            advanceUntilIdle()
            assertFalse(deviceRemember.hasRemembered(identity))
            assertEquals(VaultRouteMode.UNLOCK, replacement.state.value.mode)
            assertFalse(replacement.state.value.loading)
            assertTrue(deviceRemember.restoreBindings.isEmpty())
            replacement.leaveRoute()
        }

    @Test fun cancelledUnknownEnrollmentCleanupFailureKeepsReplacementRestoreBlocked() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val first = model(repository)
            first.enterRoute(location.accountId, location)
            advanceUntilIdle()
            first.unlock("password".toCharArray())
            advanceUntilIdle()
            deviceRemember.forgetFailure = true
            deviceRemember.unknownEnrollmentOutcome = true
            deviceRemember.beforeRemember = { first.leaveRoute() }

            first.rememberOnPhone()
            advanceUntilIdle()

            assertEquals(false, VaultDeviceRememberRevocations.await(identity))
            assertTrue(deviceRemember.hasRemembered(identity))

            val replacement = model(repository)
            replacement.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, replacement.state.value.mode)
            assertEquals(VaultRouteError.PHONE_LOCK_FAILED, replacement.state.value.error)
            assertTrue(deviceRemember.restoreBindings.isEmpty())
            replacement.leaveRoute()
        }

    @Test fun settingsResetIsFollowedByDurableSameProcessFenceRecovery() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            deviceRemember.seedRemembered(identity, repository.binding)
            VaultDeviceRememberRevocations.block(identity)

            // Settings reset revokes the record, but the failed in-process fence remains until retried.
            deviceRemember.forget(identity)
            val replacement = model(repository)
            replacement.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, replacement.state.value.mode)
            assertTrue(deviceRemember.restoreBindings.isEmpty())
            assertEquals(null, VaultDeviceRememberRevocations.await(identity))

            replacement.unlock("password".toCharArray())
            advanceUntilIdle()
            assertTrue(replacement.state.value.phoneRememberOffer)
            replacement.rememberOnPhone()
            advanceUntilIdle()
            assertTrue(deviceRemember.hasRemembered(identity))
            replacement.leaveRoute()
        }

    @Test fun differentAccountSnapshotAndCredentialRevocationEachRequireAnotherUnlock() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            listOf(false, true).forEach { credentialChange ->
                VaultUnlockSession(application).clear()
                deviceRemember = FakeDeviceRemember()
                val repository = PhoneRepository()
                val model = model(repository)
                model.enterRoute(location.accountId, location)
                advanceUntilIdle()
                model.unlock("password".toCharArray())
                advanceUntilIdle()
                model.rememberOnPhone()
                advanceUntilIdle()
                model.leaveRoute()
                if (credentialChange) {
                    repository.credentialGeneration++
                    deviceRemember.forget(identity) // Model core's explicit credential-replacement hook.
                } else {
                    repository.accountSnapshot =
                        "changed-account-row"
                    repository.binding =
                        VaultRememberBinding(
                            "11111111111111111111111111111111",
                            "1111111111111111111111111111111111111111111111111111111111111111",
                        )
                }
                model.enterRoute(location.accountId, location)
                advanceUntilIdle()
                assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
                assertEquals(0, repository.keyUnlocks)
                model.leaveRoute()
            }
        }

    @Test fun failedRememberedProofDoesNotDeleteThePersistentRecord() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val model = model(repository)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            model.rememberOnPhone()
            advanceUntilIdle()
            model.leaveRoute()
            repository.proofFails = true
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertTrue(
                model.state.value.entries
                    .isEmpty(),
            )
            assertFalse(model.state.value.loading)
            model.leaveRoute()
            repository.proofFails = false
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals(2, repository.keyUnlocks)
            assertTrue(deviceRemember.hasRemembered(identity))
            model.leaveRoute()
        }

    @Test fun passwordCompletionAfterGlobalLockCannotPopulateCache() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<Unit>? = null
            val repository = PhoneRepository().apply { beforePassword = { suspendCoroutine { pending = it } } }
            val model = model(repository)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.unlock("password".toCharArray())
            runCurrent()
            AppLock(application).lock()
            requireNotNull(pending).resume(Unit)
            advanceUntilIdle()
            model.leaveRoute()
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertEquals(0, repository.keyUnlocks)
            model.leaveRoute()
        }

    @Test fun lateRememberedProofAfterScreenOffIsClosedAndNeverPublished() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = PhoneRepository()
            val model = model(repository)
            model.enterRoute(location.accountId, location)
            advanceUntilIdle()
            model.unlock("password".toCharArray())
            advanceUntilIdle()
            model.rememberOnPhone()
            advanceUntilIdle()
            model.leaveRoute()
            var pending: Continuation<Unit>? = null
            repository.beforeKey = { suspendCoroutine { pending = it } }
            model.enterRoute(location.accountId, location)
            runCurrent()
            AppLock(application).lock()
            deviceRemember.deviceAvailable = false
            model.onDeviceLocked()
            requireNotNull(pending).resume(Unit)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertTrue(repository.sessions.last().closed)
            assertTrue(
                model.state.value.entries
                    .isEmpty(),
            )
            assertTrue(requireNotNull(repository.receivedKey).all { it == 0.toByte() })
            model.leaveRoute()
        }

    private fun model(
        repository: PhoneRepository,
        biometrics: UnusedBiometrics = UnusedBiometrics(),
        ioDispatcher: CoroutineDispatcher = Dispatchers.Main,
    ) = VaultViewModel(
        application,
        repository,
        biometrics,
        ioDispatcher = ioDispatcher,
        adapters = VaultViewModelAdapters(application, deviceRemember = deviceRemember),
    )

    private inner class PhoneRepository(
        private val offline: Boolean = false,
    ) : VaultRouteRepository {
        var accountSnapshot = "initial-account-row"
        var binding =
            VaultRememberBinding(
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
        var credentialGeneration = 0
        var passwordUnlocks = 0
        var keyUnlocks = 0
        var exports = 0
        var proofFails = false
        var beforePassword: suspend () -> Unit = {}
        var beforeKey: suspend () -> Unit = {}
        var receivedKey: ByteArray? = null
        val sessions = mutableListOf<VaultViewModelRaceTest.TestSession>()

        override suspend fun unlockAccountSnapshot(accountId: String): Any = accountSnapshot

        override suspend fun rememberBinding(accountId: String): VaultRememberBinding = binding

        override fun unlockCredentialPermit(accountId: String): () -> Boolean {
            val revision = credentialGeneration
            return { credentialGeneration == revision }
        }

        override suspend fun locations(accountId: String) = listOf(location)

        override suspend fun folders(
            accountId: String,
            location: VaultLocation,
            path: String,
        ): List<VaultFolder> = emptyList()

        override suspend fun unlock(
            accountId: String,
            target: VaultLocation,
            vaultPath: String,
            password: CharArray,
        ): VaultRouteSession {
            passwordUnlocks++
            beforePassword()
            return newSession()
        }

        override suspend fun unlockWithKeyMaterial(
            accountId: String,
            target: VaultLocation,
            vaultPath: String,
            keyMaterial: ByteArray,
        ): VaultRouteSession {
            keyUnlocks++
            receivedKey = keyMaterial
            assertArrayEquals(ByteArray(80) { 7 }, keyMaterial)
            beforeKey()
            if (proofFails) throw VaultUnlockException(VaultUnlockFailure.PASSWORD_NOT_PROVEN)
            return newSession()
        }

        private fun newSession() =
            VaultViewModelRaceTest
                .TestSession(
                    identity,
                    emptyList(),
                    exportBlock = {
                        exports++
                        ByteArray(80) { 7 }
                    },
                    isOffline = offline,
                ).also { sessions += it }
    }

    private class UnusedBiometrics(
        private val enrolled: Boolean = false,
    ) : VaultBiometricKeyStore {
        var completions = 0
        var deliveredMaterial: ByteArray? = null

        override fun hasEnrollment(identity: VaultIdentity) = enrolled

        override fun prepareEnrollment(identity: VaultIdentity): Cipher = error("unused")

        override fun completeEnrollment(
            identity: VaultIdentity,
            cipher: Cipher,
            keyMaterial: ByteArray,
        ) = Unit

        override fun cancelEnrollment(identity: VaultIdentity) = Unit

        override fun prepareUnlock(identity: VaultIdentity): Cipher = Cipher.getInstance("AES/GCM/NoPadding")

        override fun completeUnlock(
            identity: VaultIdentity,
            cipher: Cipher,
        ): ByteArray {
            completions++
            return ByteArray(80) { 7 }.also { deliveredMaterial = it }
        }

        override fun cancelUnlock(identity: VaultIdentity) = Unit

        override fun forget(identity: VaultIdentity) = Unit
    }

    private data class FakeAdmission(
        val identity: VaultIdentity,
        val binding: VaultRememberBinding,
    ) : VaultDeviceRememberAccess.Admission

    private inner class FakeDeviceRemember : VaultDeviceRememberAccess {
        private val choices = mutableMapOf<VaultIdentity, VaultRememberChoice>()
        private val bindings = mutableMapOf<VaultIdentity, VaultRememberBinding>()
        private val materials = mutableMapOf<VaultIdentity, ByteArray>()
        val restoreBindings = mutableListOf<VaultRememberBinding>()
        var beforeRemember: (() -> Unit)? = null
        var deviceAvailable = true
        var restoreAvailable = true
        var forgetFailure = false
        var unknownEnrollmentOutcome = false
        var beforeForget: (() -> Unit)? = null
        var afterForget: (() -> Unit)? = null
        var beginCalls = 0
        var lastReceivedMaterial: ByteArray? = null

        override fun isSupported() = deviceAvailable

        override fun begin(
            identity: VaultIdentity,
            binding: VaultRememberBinding,
        ): VaultDeviceRememberAccess.Admission {
            beginCalls++
            return FakeAdmission(identity, binding)
        }

        override fun remember(
            admission: VaultDeviceRememberAccess.Admission?,
            identity: VaultIdentity,
            binding: VaultRememberBinding,
            verifiedKeyMaterial: ByteArray,
            permit: () -> Boolean,
        ): Boolean {
            lastReceivedMaterial = verifiedKeyMaterial
            beforeRemember?.invoke()
            if (unknownEnrollmentOutcome) {
                choices[identity] = VaultRememberChoice.REMEMBERED
                bindings[identity] = binding
                materials[identity] = verifiedKeyMaterial.copyOf()
                throw VaultDeviceRememberOutcomeUnknownException()
            }
            val grant = admission as? FakeAdmission
            val grantMatches = grant?.let { it.identity == identity && it.binding == binding } == true
            if (!(grantMatches && permit())) return false
            materials.remove(identity)?.fill(0)
            choices[identity] = VaultRememberChoice.REMEMBERED
            bindings[identity] = binding
            materials[identity] = verifiedKeyMaterial.copyOf()
            return true
        }

        override fun restore(
            identity: VaultIdentity,
            binding: VaultRememberBinding,
            permit: () -> Boolean,
        ): VaultDeviceRememberKey? {
            restoreBindings += binding
            val deviceUsable = deviceAvailable && restoreAvailable
            val recordMatches = choices[identity] == VaultRememberChoice.REMEMBERED && bindings[identity] == binding
            val callerAllowed = runCatching(permit).getOrDefault(false)
            val restoredMaterial =
                if (deviceUsable &&
                    recordMatches &&
                    callerAllowed
                ) {
                    materials[identity]?.copyOf()
                } else {
                    null
                }
            return restoredMaterial?.let { material ->
                object : VaultDeviceRememberKey {
                    private var closed = false
                    override val material = material

                    override fun isCurrent() =
                        !closed &&
                            deviceAvailable &&
                            choices[identity] == VaultRememberChoice.REMEMBERED &&
                            bindings[identity] == binding &&
                            runCatching(permit).getOrDefault(false)

                    override fun close() {
                        material.fill(0)
                        closed = true
                    }
                }
            }
        }

        override fun choice(identity: VaultIdentity) = choices[identity]

        override fun hasRemembered(identity: VaultIdentity) = choices[identity] == VaultRememberChoice.REMEMBERED

        override fun decline(identity: VaultIdentity) {
            choices[identity] = VaultRememberChoice.DECLINED
            bindings.remove(identity)
            materials.remove(identity)?.fill(0)
        }

        override fun forget(identity: VaultIdentity) {
            beforeForget?.invoke()
            check(!forgetFailure) { "synthetic forget failure" }
            choices.remove(identity)
            bindings.remove(identity)
            materials.remove(identity)?.fill(0)
            afterForget?.invoke()
        }

        fun seedRemembered(
            identity: VaultIdentity,
            binding: VaultRememberBinding,
        ) {
            choices[identity] = VaultRememberChoice.REMEMBERED
            bindings[identity] = binding
            materials[identity] = ByteArray(80) { 7 }
        }
    }
}
