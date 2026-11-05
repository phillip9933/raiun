package eu.opencloud.android.next.ui

import android.app.Application
import android.content.Context
import androidx.test.core.app.ApplicationProvider
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
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.util.concurrent.Executors
import javax.crypto.Cipher

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultUnlockTimingTest {
    @Before fun allowRememberedUnlock() {
        val application = ApplicationProvider.getApplicationContext<Application>()
        check(
            application
                .getSharedPreferences("vault-unlock-policy", Context.MODE_PRIVATE)
                .edit()
                .putBoolean("ask-every-time", false)
                .commit(),
        )
    }

    @Test fun stagesEndAtPublicationAndEveryReusedKeyGuardStillRuns() =
        runTest {
            var clock = 0L
            val events = mutableListOf<Measurement>()
            val fixture =
                Fixture(
                    this,
                    StandardTestDispatcher(testScheduler),
                    recorder =
                        VaultUnlockTiming({ ++clock }) { stage, outcome, nanos ->
                            events += Measurement(stage, outcome, nanos)
                        },
                )
            fixture.afterOpen = { awaitCancellation() }
            fixture.start()
            runCurrent()

            assertEquals(VaultRouteMode.CONTENTS, fixture.state.value.mode)
            assertSame(fixture.opened, fixture.lifecycle.session)
            assertEquals(6, fixture.currentChecks)
            assertEquals(3, fixture.accountReads)
            assertEquals(2, fixture.bindingReads)
            assertEquals(1, fixture.rememberedReads)
            assertEquals(2, fixture.supportChecks)
            assertEquals(
                listOf(
                    VaultUnlockStage.LOCAL_RESTORE,
                    VaultUnlockStage.SERVER_VERIFICATION,
                    VaultUnlockStage.INITIAL_DIRECTORY,
                    VaultUnlockStage.FINAL_ADMISSION,
                    VaultUnlockStage.TOTAL,
                ),
                events.map { it.stage },
            )
            assertTrue(events.all { it.outcome == VaultUnlockOutcome.SUCCESS })
            assertEquals(listOf(1L, 1L, 1L, 1L, 9L), events.map { it.nanos })
            fixture.lifecycle.leave()
            advanceUntilIdle()
        }

    @Test fun cancellingProofRecordsCancellationAndClosesOwnedKey() =
        runTest {
            val events = mutableListOf<Measurement>()
            val fixture = Fixture(this, StandardTestDispatcher(testScheduler), recorder = recording(events))
            fixture.beforeProof = { awaitCancellation() }
            fixture.start()
            runCurrent()
            fixture.lifecycle.invalidateRequests()
            advanceUntilIdle()

            assertNull(fixture.lifecycle.session)
            assertTrue(fixture.keyClosed)
            assertEquals(
                listOf(VaultUnlockOutcome.SUCCESS, VaultUnlockOutcome.CANCELLED, VaultUnlockOutcome.CANCELLED),
                events.map { it.outcome },
            )
            assertEquals(VaultUnlockStage.SERVER_VERIFICATION, events[1].stage)
            fixture.lifecycle.leave()
        }

    @Test fun proofFailureRetainsFallbackAndSanitizedOutcome() =
        runTest {
            val events = mutableListOf<Measurement>()
            val fixture = Fixture(this, StandardTestDispatcher(testScheduler), recorder = recording(events))
            fixture.beforeProof = { error("Synthetic failure must never reach the measurement sink") }
            fixture.start()
            advanceUntilIdle()

            assertNull(fixture.lifecycle.session)
            assertTrue(fixture.keyClosed)
            assertEquals("US7", fixture.state.value.phoneSessionIssueCode)
            assertEquals(
                listOf(VaultUnlockOutcome.SUCCESS, VaultUnlockOutcome.FAILURE, VaultUnlockOutcome.FAILURE),
                events.map { it.outcome },
            )
            fixture.lifecycle.leave()
        }

    @Test fun failingClockAndObserverCannotAffectAdmission() =
        runTest {
            val brokenRecorders =
                listOf(
                    VaultUnlockTiming({ error("Synthetic clock failure") }) { _, _, _ -> error("Unreachable") },
                    VaultUnlockTiming({ 1L }) { _, _, _ -> error("Synthetic observer failure") },
                )
            brokenRecorders.forEach { recorder ->
                val fixture = Fixture(this, StandardTestDispatcher(testScheduler), recorder = recorder)
                fixture.start()
                advanceUntilIdle()
                assertEquals(VaultRouteMode.CONTENTS, fixture.state.value.mode)
                assertEquals(6, fixture.currentChecks)
                assertTrue(fixture.keyClosed)
                fixture.lifecycle.leave()
            }
        }

    @Test fun cancellationFromCompletedAdmissionObserverCannotCloseAdoptedSession() =
        runTest {
            lateinit var fixture: Fixture
            fixture =
                Fixture(
                    this,
                    StandardTestDispatcher(testScheduler),
                    recorder =
                        VaultUnlockTiming({ 1L }) { stage, outcome, _ ->
                            if (stage == VaultUnlockStage.FINAL_ADMISSION && outcome == VaultUnlockOutcome.SUCCESS) {
                                fixture.lifecycle.invalidateRequests()
                            }
                        },
                )
            fixture.start()
            advanceUntilIdle()
            assertSame(fixture.opened, fixture.lifecycle.session)
            assertFalse(fixture.sessionClosed)
            assertFalse(fixture.snapshotClosed)
            fixture.lifecycle.leave()
        }

    @Test fun revocationAtEveryCurrentKeyCheckStillDeniesAdmission() =
        runTest {
            for (revokedAt in 1..6) {
                val fixture = Fixture(this, StandardTestDispatcher(testScheduler))
                fixture.revokeAt = revokedAt
                fixture.start()
                advanceUntilIdle()
                assertNull("Current-key guard $revokedAt must deny admission", fixture.lifecycle.session)
                assertTrue(fixture.keyClosed)
                fixture.lifecycle.leave()
            }
        }

    @Test fun accountAndBindingReplacementStillDenyRememberedAdmission() =
        runTest {
            for ((accountRead, bindingRead) in listOf(2 to Int.MAX_VALUE, 3 to Int.MAX_VALUE, Int.MAX_VALUE to 2)) {
                val events = mutableListOf<Measurement>()
                val fixture = Fixture(this, StandardTestDispatcher(testScheduler), recorder = recording(events))
                fixture.replaceAccountAt = accountRead
                fixture.replaceBindingAt = bindingRead
                fixture.start()
                advanceUntilIdle()
                assertNull(fixture.lifecycle.session)
                assertTrue(fixture.sessionClosed)
                assertTrue(fixture.snapshotClosed)
                assertTrue(fixture.keyClosed)
                assertEquals(VaultUnlockOutcome.FAILURE, events.last().outcome)
                fixture.lifecycle.leave()
            }
        }

    /** Wall-clock fixture; injected service delays are synthetic, not Android Keystore/network results. */
    @Test fun syntheticServiceLatencyMeasurement() {
        val output = System.getenv("RAIUN_UNLOCK_BENCHMARK_OUTPUT")
        Executors.newSingleThreadExecutor().asCoroutineDispatcher().use { dispatcher ->
            runBlocking(dispatcher) {
                val samples = mutableListOf<List<Measurement>>()
                repeat(7) { sample ->
                    val events = mutableListOf<Measurement>()
                    val fixture = Fixture(this, Dispatchers.IO, syntheticDelayMillis = 10, recorder = recording(events))
                    fixture.start()
                    withTimeout(10_000) { fixture.state.first { it.mode == VaultRouteMode.CONTENTS } }
                    // The state is published immediately before the two final timing records on this same dispatcher.
                    assertEquals(VaultUnlockStage.TOTAL, events.last().stage)
                    assertEquals(6, fixture.currentChecks)
                    if (sample >= 2) samples += events.toList()
                    fixture.lifecycle.leave()
                }
                val report =
                    buildString {
                        appendLine("scope=synthetic-services-real-dispatchers-wall-clock")
                        appendLine("injectedDelayMillis=10 warmups=2 measured=5")
                        appendLine("notPhysicalKeystore=true notLiveServer=true")
                        samples.forEachIndexed { index, measurements ->
                            measurements.forEach { item ->
                                appendLine(
                                    "sample=$index stage=${item.stage} outcome=${item.outcome} elapsedNanos=${item.nanos}",
                                )
                            }
                        }
                    }
                println(report)
                output?.let { destination -> File(destination).apply { parentFile.mkdirs() }.writeText(report) }
            }
        }
    }

    private fun recording(events: MutableList<Measurement>) =
        VaultUnlockTiming { stage, outcome, nanos ->
            events += Measurement(stage, outcome, nanos)
        }

    private data class Measurement(
        val stage: VaultUnlockStage,
        val outcome: VaultUnlockOutcome,
        val nanos: Long,
    )

    private class Fixture(
        scope: CoroutineScope,
        io: CoroutineDispatcher,
        private val syntheticDelayMillis: Long = 0,
        recorder: VaultUnlockTiming? = null,
    ) {
        private val location = VaultViewModelRaceTest.location
        private val identity = VaultViewModelRaceTest.identity
        private val binding =
            VaultRememberBinding(
                "0123456789abcdef0123456789abcdef",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
        private val target = VaultSessionTarget(location, location.vaultPath, location.title, location.remoteVaultId)
        val state = MutableStateFlow(VaultRouteState(mode = VaultRouteMode.UNLOCK))
        var currentChecks = 0
        var accountReads = 0
        var bindingReads = 0
        var rememberedReads = 0
        var supportChecks = 0
        var revokeAt = Int.MAX_VALUE
        var replaceAccountAt = Int.MAX_VALUE
        var replaceBindingAt = Int.MAX_VALUE
        var keyClosed = false
        var sessionClosed = false
        var snapshotClosed = false
        var beforeProof: suspend () -> Unit = {}
        var afterOpen: suspend () -> Unit = {}

        private fun serviceDelay() {
            if (syntheticDelayMillis > 0) Thread.sleep(syntheticDelayMillis)
        }

        private val snapshot =
            object : VaultRouteDirectorySnapshot {
                override val totalCount = 0L

                override suspend fun page(
                    offset: Long,
                    limit: Int,
                ): List<VaultFolder> = emptyList()

                override fun close() {
                    snapshotClosed = true
                }
            }
        val opened =
            object : VaultRouteSession by VaultViewModelRaceTest.TestSession(identity, emptyList()) {
                override suspend fun openDirectory(
                    path: String,
                    showHidden: Boolean,
                    excludedPath: String?,
                ): VaultRouteDirectorySnapshot {
                    serviceDelay()
                    return snapshot
                }

                override fun close() {
                    sessionClosed = true
                }
            }
        private val repository =
            object : VaultRouteRepository by VaultViewModelRaceTest.TestRepository(unlockBlock = { _, _, _, _ ->
                error("Remembered fixture must not use password unlock")
            }) {
                override suspend fun unlockAccountSnapshot(accountId: String): Any {
                    serviceDelay()
                    accountReads++
                    return if (accountReads >= replaceAccountAt) "replaced" else "synthetic-account-row"
                }

                override suspend fun rememberBinding(accountId: String): VaultRememberBinding {
                    serviceDelay()
                    bindingReads++
                    return if (bindingReads >= replaceBindingAt) binding.copy(incarnation = "f".repeat(32)) else binding
                }

                override fun unlockCredentialPermit(accountId: String): () -> Boolean = { true }

                override suspend fun unlockWithKeyMaterial(
                    accountId: String,
                    target: VaultLocation,
                    vaultPath: String,
                    keyMaterial: ByteArray,
                ): VaultRouteSession {
                    beforeProof()
                    serviceDelay()
                    return opened
                }
            }
        private val remember =
            object : VaultDeviceRememberAccess {
                override fun isSupported(): Boolean {
                    serviceDelay()
                    supportChecks++
                    return true
                }

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
                ): VaultDeviceRememberKey {
                    serviceDelay()
                    return object : VaultDeviceRememberKey {
                        override val material = ByteArray(80) { 7 }

                        override fun isCurrent(): Boolean {
                            serviceDelay()
                            currentChecks++
                            return currentChecks < revokeAt
                        }

                        override fun close() {
                            keyClosed = true
                            material.fill(0)
                        }
                    }
                }

                override fun choice(identity: VaultIdentity): VaultRememberChoice {
                    serviceDelay()
                    return VaultRememberChoice.REMEMBERED
                }

                override fun hasRemembered(identity: VaultIdentity): Boolean {
                    serviceDelay()
                    rememberedReads++
                    return true
                }

                override fun decline(identity: VaultIdentity) = Unit

                override fun forget(identity: VaultIdentity) = Unit
            }
        private val directory: VaultDirectoryContent =
            VaultDirectoryContent(
                state,
                object : VaultDirectoryOwner {
                    override fun showHidden() = false

                    override fun isCurrent(
                        opened: VaultRouteSession,
                        token: Long,
                        account: String,
                    ) = lifecycle.isCurrent(token, account)

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
                Biometrics,
                Preferences,
                io,
                remember,
                scope,
                state,
                directory,
                object : VaultSessionPresentation {
                    override fun invalidateRoutePresentation() = Unit

                    override fun closeSessionContent() = directory.close()

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
                recorder,
            )

        fun start() {
            lifecycle.enter(location.accountId)
            lifecycle.replaceTarget(target)
            lifecycle.tryPhoneSessionUnlock(target, lifecycle.generation)
        }
    }

    private object Biometrics : VaultBiometricKeyStore {
        override fun hasEnrollment(identity: VaultIdentity) = false

        override fun prepareEnrollment(identity: VaultIdentity): Cipher = error("Unused")

        override fun completeEnrollment(
            identity: VaultIdentity,
            cipher: Cipher,
            keyMaterial: ByteArray,
        ) = Unit

        override fun cancelEnrollment(identity: VaultIdentity) = Unit

        override fun prepareUnlock(identity: VaultIdentity): Cipher = error("Unused")

        override fun completeUnlock(
            identity: VaultIdentity,
            cipher: Cipher,
        ): ByteArray = error("Unused")

        override fun cancelUnlock(identity: VaultIdentity) = Unit

        override fun forget(identity: VaultIdentity) = Unit
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
}
