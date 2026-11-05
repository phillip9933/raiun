package eu.opencloud.android.next.ui

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultRootManagementTest {
    @After
    fun resetMainDispatcher() {
        Dispatchers.resetMain()
    }

    @Test fun `management lease rejects every changed location binding and stale revision`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val fixture = Fixture()
            fixture.open()
            advanceUntilIdle()
            val model = fixture.model
            val revision = model.state.value.lockRevision
            val lease = requireNotNull(model.managementTarget(revision))
            val changed =
                listOf(
                    lease.copy(accountId = "other"),
                    lease.copy(canonicalServer = "https://other.example"),
                    lease.copy(driveId = "other"),
                    lease.copy(remoteVaultId = "other"),
                    lease.copy(sourceRootId = "other"),
                    lease.copy(vaultPath = "other"),
                    lease.copy(rootWebDavUrl = "https://cloud.example/other"),
                    lease.copy(kind = VaultLocationKind.SPACE_VAULT),
                )
            changed.forEach { candidate ->
                assertFalse(model.isManagementUnlocked(candidate, revision))
                model.managedSpaceChanged(candidate.copy(title = "Stale"), revision)
            }
            assertEquals(location.title, model.state.value.selectedTitle)
            model.managedSpaceChanged(lease.copy(title = "Accepted"), revision)
            assertEquals("Accepted", model.state.value.selectedTitle)
            model.lock()
            assertNull(model.managementTarget(revision))
            model.renameRoot("Rejected", revision)
            model.deleteRoot(revision)
            assertEquals(listOf("close"), fixture.events)
            model.leaveRoute()
        }

    @Test fun `nested paths offline sessions and Space roots cannot mutate a folder root`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val scenarios =
                listOf(
                    Fixture(nested = true),
                    Fixture(offline = true),
                    Fixture(initialLocation = location.copy(kind = VaultLocationKind.SPACE_VAULT)),
                )
            scenarios.forEach { fixture ->
                fixture.open()
                advanceUntilIdle()
                val model = fixture.model
                if (fixture.nested) {
                    model.openVaultFolder(
                        model.state.value.entries
                            .single()
                            .id,
                    )
                    advanceUntilIdle()
                    assertEquals("nested", model.state.value.currentPath)
                }
                val revision = model.state.value.lockRevision
                if (fixture.nested || fixture.offline) assertNull(model.managementTarget(revision))
                model.renameRoot("Rejected", revision)
                model.deleteRoot(revision)
                advanceUntilIdle()
                assertTrue(fixture.events.isEmpty())
                model.leaveRoute()
            }
        }

    @Test fun `rename cleans old offline identity before relocking with changed path and title`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val changed = location.copy(title = "Renamed", vaultPath = "renamed", remoteVaultId = "new-root")
            val fixture = Fixture(rename = { changed })
            fixture.open()
            advanceUntilIdle()
            val revision = fixture.model.state.value.lockRevision
            fixture.model.renameRoot("Renamed", revision)
            advanceUntilIdle()
            assertEquals(listOf("rename", "offline", "close"), fixture.events)
            assertEquals(listOf(identity), fixture.removed)
            assertEquals(VaultRouteMode.UNLOCK, fixture.model.state.value.mode)
            assertEquals("Renamed", fixture.model.state.value.selectedTitle)
            assertTrue(fixture.model.state.value.lockRevision > revision)
            fixture.model.unlock("synthetic".toCharArray())
            advanceUntilIdle()
            assertEquals(changed, fixture.unlockTargets.last())
            fixture.model.leaveRoute()
        }

    @Test fun `rename finalization failure after closing still relocks the owned route`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val fixture = Fixture(rename = { location.copy(accountId = "invalid-rename-owner") })
            fixture.open()
            advanceUntilIdle()
            val revision = fixture.model.state.value.lockRevision
            fixture.model.renameRoot("Attempt", revision)
            advanceUntilIdle()
            assertEquals(listOf("rename", "offline", "close"), fixture.events)
            assertEquals(VaultRouteMode.UNLOCK, fixture.model.state.value.mode)
            assertEquals(VaultRouteError.OPERATION, fixture.model.state.value.error)
            assertEquals(location.title, fixture.model.state.value.selectedTitle)
            assertTrue(fixture.model.state.value.lockRevision > revision)
            fixture.model.leaveRoute()
        }

    @Test fun `rename preserves cleanup-required enrollment status when metadata lookup fails`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val fixture = Fixture(rename = { location.copy(title = "Renamed") })
            fixture.open()
            advanceUntilIdle()
            fixture.failEnrollment = true
            fixture.model.renameRoot("Renamed", fixture.model.state.value.lockRevision)
            advanceUntilIdle()
            assertEquals(VaultRouteMode.UNLOCK, fixture.model.state.value.mode)
            assertEquals("Renamed", fixture.model.state.value.selectedTitle)
            assertTrue(fixture.model.state.value.biometricEnrolled)
            assertTrue(fixture.model.state.value.biometricNeedsForget)
            assertFalse(fixture.model.state.value.loading)
            fixture.model.leaveRoute()
        }

    @Test fun `delete cleans offline identity before closing and clearing the target`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val fixture = Fixture()
            fixture.open()
            advanceUntilIdle()
            fixture.model.deleteRoot(fixture.model.state.value.lockRevision)
            advanceUntilIdle()
            assertEquals(listOf("delete", "offline", "close"), fixture.events)
            assertEquals(listOf(identity), fixture.removed)
            assertEquals(VaultRouteMode.CATALOG, fixture.model.state.value.mode)
            assertNull(fixture.model.state.value.selectedLocation)
            assertEquals(listOf(identity), fixture.biometric.forgottenIdentities)
            fixture.model.leaveRoute()
        }

    @Test fun `failed mutation and failed offline cleanup both relock without replay`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            listOf(false, true).forEach { failCleanup ->
                val fixture =
                    Fixture(
                        rename = { if (failCleanup) location else error("Synthetic uncertain mutation") },
                        remove = { if (failCleanup) error("Synthetic uncertain cleanup") },
                    )
                fixture.open()
                advanceUntilIdle()
                val revision = fixture.model.state.value.lockRevision
                fixture.model.renameRoot("Attempt", revision)
                advanceUntilIdle()
                assertEquals(VaultRouteMode.UNLOCK, fixture.model.state.value.mode)
                assertEquals(VaultRouteError.OPERATION, fixture.model.state.value.error)
                assertTrue(fixture.closed)
                assertTrue(fixture.model.state.value.lockRevision > revision)
                fixture.model.renameRoot("Replay", revision)
                fixture.model.deleteRoot(revision)
                advanceUntilIdle()
                assertEquals(1, fixture.events.count { it == "rename" })
                assertEquals(if (failCleanup) listOf(identity) else emptyList<VaultIdentity>(), fixture.removed)
                fixture.model.leaveRoute()
            }
        }

    @Test fun `late rename and delete success clean only their captured identity after account replacement`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            listOf(false, true).forEach { delete ->
                var pending: Continuation<Unit>? = null
                val fixture =
                    Fixture(
                        rename = {
                            suspendCoroutine<Unit> { pending = it }
                            location.copy(title = "Late")
                        },
                        delete = { suspendCoroutine { pending = it } },
                    )
                fixture.open()
                advanceUntilIdle()
                fixture.mutate(delete)
                runCurrent()
                fixture.openReplacement()
                advanceUntilIdle()
                val replacement = fixture.model.state.value
                requireNotNull(pending).resume(Unit)
                advanceUntilIdle()
                assertEquals(listOf(identity), fixture.removed)
                assertEquals(replacement, fixture.model.state.value)
                assertFalse(fixture.replacementClosed)
                assertTrue(fixture.biometric.forgottenIdentities.isEmpty())
                fixture.model.leaveRoute()
            }
        }

    @Test fun `late uncertain rename and delete outcomes cannot relock a newer same-account session`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            listOf(false, true).forEach { delete ->
                var pending: Continuation<Unit>? = null
                val fixture =
                    Fixture(
                        rename = {
                            suspendCoroutine<Unit> { pending = it }
                            location
                        },
                        delete = { suspendCoroutine { pending = it } },
                    )
                fixture.open()
                advanceUntilIdle()
                fixture.mutate(delete)
                runCurrent()
                fixture.model.leaveRoute()
                fixture.openReplacement(sameAccount = true)
                advanceUntilIdle()
                val replacement = fixture.model.state.value
                requireNotNull(pending).resumeWithException(IllegalStateException("Synthetic uncertain result"))
                advanceUntilIdle()
                assertEquals(replacement, fixture.model.state.value)
                assertFalse(fixture.replacementClosed)
                assertTrue(fixture.removed.isEmpty())
                fixture.model.leaveRoute()
            }
        }

    @Test fun `management lifecycle cleanup locks first and late completion cannot call a newer route`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<Unit>? = null
            val fixture = Fixture(remove = { suspendCoroutine { pending = it } })
            fixture.open()
            advanceUntilIdle()
            var completions = 0
            fixture.model.managedSpaceLifecycleChanged(fixture.model.state.value.lockRevision) { completions++ }
            assertTrue(fixture.closed)
            assertEquals(VaultRouteMode.UNLOCK, fixture.model.state.value.mode)
            runCurrent()
            fixture.openReplacement()
            advanceUntilIdle()
            val replacement = fixture.model.state.value
            requireNotNull(pending).resume(Unit)
            advanceUntilIdle()
            assertEquals(listOf(identity), fixture.removed)
            assertEquals(0, completions)
            assertEquals(replacement, fixture.model.state.value)
            assertFalse(fixture.replacementClosed)
            fixture.model.leaveRoute()
        }

    @Suppress("LongParameterList") // Independent synthetic boundaries exercise mutation and cleanup outcomes.
    private class Fixture(
        private val initialLocation: VaultLocation = location,
        val nested: Boolean = false,
        val offline: Boolean = false,
        private val rename: suspend () -> VaultLocation = { location },
        private val delete: suspend () -> Unit = {},
        private val remove: suspend () -> Unit = {},
    ) {
        val events = mutableListOf<String>()
        val removed = mutableListOf<VaultIdentity>()
        val unlockTargets = mutableListOf<VaultLocation>()
        val biometric = VaultViewModelRaceTest.TestBiometricStore()
        var failEnrollment = false
        private val biometricAccess =
            object : VaultBiometricKeyStore by biometric {
                override fun hasEnrollment(identity: VaultIdentity): Boolean {
                    check(!failEnrollment) { "Synthetic unavailable enrollment metadata" }
                    return biometric.hasEnrollment(identity)
                }
            }
        var closed = false
        var replacementClosed = false
        private var replacing = false
        private val repository =
            object : VaultRouteRepository by VaultViewModelRaceTest.TestRepository({ _, _, _, _ -> error("Unused") }) {
                override suspend fun unlock(
                    accountId: String,
                    target: VaultLocation,
                    vaultPath: String,
                    password: CharArray,
                ): VaultRouteSession {
                    unlockTargets += target
                    val replacement = replacing
                    val entries =
                        if (nested) {
                            listOf(VaultViewModelRaceTest().folder("nested").copy(isFolder = true))
                        } else {
                            emptyList()
                        }
                    val base =
                        VaultViewModelRaceTest.TestSession(
                            VaultIdentity(accountId, target.canonicalServer, target.driveId, target.remoteVaultId),
                            entries,
                            isOffline = offline,
                        )
                    return object : VaultRouteSession by base {
                        override suspend fun renameVaultRoot(newName: String): VaultLocation {
                            events += "rename"
                            return rename()
                        }

                        override suspend fun deleteVaultRoot() {
                            events += "delete"
                            delete()
                        }

                        override fun close() {
                            if (replacement) {
                                replacementClosed = true
                            } else {
                                closed = true
                                events += "close"
                            }
                            base.close()
                        }
                    }
                }

                override suspend fun removeOffline(identity: VaultIdentity) {
                    events += "offline"
                    removed += identity
                    remove()
                }
            }
        private val application = ApplicationProvider.getApplicationContext<Application>()
        val model =
            VaultViewModel(
                application,
                repository,
                biometricAccess,
                VaultViewModelRaceTest.TestVaultOfferPreferences(),
                Dispatchers.Main,
                VaultViewModelAdapters(
                    application,
                    deviceRemember = VaultViewModelRaceTest.UnsupportedDeviceRememberAccess,
                ),
            )

        fun open() {
            model.enterRoute(initialLocation.accountId, initialLocation)
            model.unlock("synthetic".toCharArray())
        }

        fun mutate(delete: Boolean) {
            if (delete) {
                model.deleteRoot(model.state.value.lockRevision)
            } else {
                model.renameRoot("Attempt", model.state.value.lockRevision)
            }
        }

        fun openReplacement(sameAccount: Boolean = false) {
            replacing = true
            val replacement =
                location.copy(
                    accountId = if (sameAccount) location.accountId else "replacement-account",
                    remoteVaultId = "replacement-root",
                    title = "Replacement",
                )
            model.enterRoute(replacement.accountId, replacement)
            model.unlock("synthetic".toCharArray())
        }
    }

    companion object {
        private val identity = VaultViewModelRaceTest.identity
        private val location = VaultViewModelRaceTest.location
    }
}
