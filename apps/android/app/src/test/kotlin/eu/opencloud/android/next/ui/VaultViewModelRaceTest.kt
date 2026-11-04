package eu.opencloud.android.next.ui

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.security.VaultRememberChoice
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.core.sync.VaultUnlockException
import eu.opencloud.android.next.core.sync.VaultUnlockFailure
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.net.UnknownHostException
import javax.crypto.Cipher
import kotlin.coroutines.Continuation
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultViewModelRaceTest {
    @After
    fun resetMainDispatcher() {
        Dispatchers.resetMain()
    }

    @Test fun `encrypted operations preserve actionable failure reasons`() {
        val cases =
            mapOf(
                OpenCloudError.DirectoryListingTooLarge to VaultRouteError.LISTING_TOO_LARGE,
                OpenCloudError.EncryptedOfflineIndexFull to VaultRouteError.OFFLINE_INDEX_FULL,
                OpenCloudError.LocalStorage to VaultRouteError.LOCAL_STORAGE,
                OpenCloudError.LocalStorageWriteFailed to VaultRouteError.LOCAL_SAVE,
                OpenCloudError.SourceUnavailable to VaultRouteError.SOURCE_UNAVAILABLE,
                OpenCloudError.SourceChanged to VaultRouteError.SOURCE_CHANGED,
                OpenCloudError.SourcePermissionDenied to VaultRouteError.SOURCE_PERMISSION,
                OpenCloudError.DownloadIntegrity to VaultRouteError.INTEGRITY,
                OpenCloudError.QuotaExceeded to VaultRouteError.REMOTE_QUOTA,
                OpenCloudError.Conflict to VaultRouteError.NAME_CONFLICT,
                OpenCloudError.NotReady(5) to VaultRouteError.SERVER_BUSY,
            )
        cases.forEach { (failure, expected) ->
            assertEquals(expected, classifyVaultFailure(OpenCloudException(failure), VaultRouteError.OPERATION))
        }
    }

    @Test
    fun lateUnlockAfterLockClosesSessionWithoutPublishingContents() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pendingUnlock: Continuation<VaultRouteSession>? = null
            val lateSession = TestSession(identity, listOf(folder("private name")))
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> suspendCoroutine { pendingUnlock = it } })
            val viewModel = newViewModel(repository)
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )

            val password = "secret".toCharArray()
            viewModel.unlock(password)
            runCurrent()
            viewModel.lock()
            requireNotNull(pendingUnlock).resume(lateSession)
            advanceUntilIdle()

            assertEquals(VaultRouteMode.UNLOCK, viewModel.state.value.mode)
            assertTrue(
                viewModel.state.value.entries
                    .isEmpty(),
            )
            assertTrue(lateSession.closed)
            assertTrue(password.all { it == '\u0000' })
            viewModel.leaveRoute()
        }

    @Test fun `offline verification refreshes a live unlocked folder`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var completions = 0
            val opened =
                TestSession(
                    identity,
                    listOf(folder("private name")),
                    offlineBlock = { completions++ },
                    offlineStatus = { completions > 0 },
                )
            val model = newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> opened }))
            model.enterRoute(ACCOUNT)
            runCurrent()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("secret".toCharArray())
            advanceUntilIdle()

            assertEquals(1, completions)
            assertEquals(1, opened.listCalls)
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals(
                true,
                model.state.value.entries
                    .single()
                    .offlineAvailable,
            )
            model.leaveRoute()
        }

    @Test fun `unlock recovers receipts with an empty queue and a retry of the same download verifies again`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val pendingIds = MutableStateFlow<String?>(null)
            var completions = 0
            val opened =
                TestSession(
                    identity,
                    listOf(folder("private name")),
                    offlineBlock = { completions++ },
                    pendingOfflineIds = pendingIds,
                )
            val model = newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> opened }))
            try {
                model.enterRoute(ACCOUNT)
                runCurrent()
                model.selectLocation(
                    model.state.value.locations
                        .single()
                        .id,
                )
                model.unlock("secret".toCharArray())
                advanceUntilIdle()
                assertEquals(1, completions)

                pendingIds.value = "same-download"
                advanceUntilIdle()
                assertEquals(2, completions)
                pendingIds.value = null
                advanceUntilIdle()
                assertEquals(2, completions)
                pendingIds.value = "same-download"
                advanceUntilIdle()
                assertEquals(3, completions)
            } finally {
                model.leaveRoute()
            }
        }

    @Test fun `late offline verification cannot publish after locking`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pending: Continuation<Unit>? = null
            val opened =
                TestSession(
                    identity,
                    listOf(folder("private name")),
                    offlineBlock = { suspendCoroutine { pending = it } },
                )
            val model = newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> opened }))
            model.enterRoute(ACCOUNT)
            runCurrent()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("secret".toCharArray())
            runCurrent()
            model.lock()
            requireNotNull(pending).resume(Unit)
            advanceUntilIdle()

            assertEquals(1, opened.listCalls)
            assertEquals(VaultRouteMode.UNLOCK, model.state.value.mode)
            assertTrue(
                model.state.value.entries
                    .isEmpty(),
            )
            assertTrue(opened.closed)
            model.leaveRoute()
        }

    @Test fun `first offline pin appears after authenticating an empty unlock anchor`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val entries = mutableListOf<VaultFolder>()
            val opened =
                TestSession(
                    identity,
                    entries,
                    offlineBlock = { entries.add(folder("new offline file")) },
                    isOffline = true,
                )
            val model = newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> opened }))
            model.enterRoute(ACCOUNT)
            runCurrent()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("secret".toCharArray())
            advanceUntilIdle()

            assertEquals(2, opened.listCalls)
            assertEquals(
                "new offline file",
                model.state.value.entries
                    .single()
                    .name,
            )
            assertTrue(model.state.value.offline)
            model.leaveRoute()
        }

    @Test
    fun passwordIsClearedWhenLockCancelsUnlockBeforeItStarts() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> error("Canceled before unlock starts") })
            val viewModel = newViewModel(repository)
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )

            val password = "secret".toCharArray()
            viewModel.unlock(password)
            viewModel.lock()
            advanceUntilIdle()

            assertTrue(password.all { it == '\u0000' })
            assertEquals(VaultRouteMode.UNLOCK, viewModel.state.value.mode)
            viewModel.leaveRoute()
        }

    @Test
    fun keyMaterialExportFinishingAfterLockIsClearedAndSessionIsClosed() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pendingExport: Continuation<ByteArray>? = null
            val unlockedSession =
                TestSession(
                    identity = identity,
                    entries = listOf(folder("private name")),
                    exportBlock = { suspendCoroutine { pendingExport = it } },
                )
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> unlockedSession })
            val viewModel = newViewModel(repository)
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )
            viewModel.unlock("secret".toCharArray())
            runCurrent()

            viewModel.lock()
            val keyMaterial = ByteArray(80) { 0x5A }
            requireNotNull(pendingExport).resume(keyMaterial)
            advanceUntilIdle()

            assertEquals(VaultRouteMode.UNLOCK, viewModel.state.value.mode)
            assertTrue(
                viewModel.state.value.entries
                    .isEmpty(),
            )
            assertTrue(keyMaterial.all { it == 0.toByte() })
            assertTrue(unlockedSession.closed)
            viewModel.leaveRoute()
        }

    @Test
    fun unlockWithChangedRemoteIdentityDoesNotPublishEntries() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val mismatchedSession =
                TestSession(
                    identity = identity.copy(remoteVaultId = "different-vault"),
                    entries = listOf(folder("private name")),
                )
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> mismatchedSession })
            val viewModel = newViewModel(repository)
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )
            viewModel.unlock("secret".toCharArray())
            advanceUntilIdle()

            assertEquals(VaultRouteMode.UNLOCK, viewModel.state.value.mode)
            assertEquals(VaultRouteError.VAULT_CHANGED, viewModel.state.value.error)
            assertTrue(
                viewModel.state.value.entries
                    .isEmpty(),
            )
            assertTrue(mismatchedSession.closed)
            assertEquals(0, mismatchedSession.listCalls)
            viewModel.leaveRoute()
        }

    @Test
    fun directVaultEntrySelectsUnlockTargetWithoutLoadingSeparateCatalog() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> error("Unlock is not used in this test.") })
            val viewModel = newViewModel(repository)

            viewModel.enterRoute(ACCOUNT, location)
            runCurrent()

            assertEquals(0, repository.locationsCalls)
            assertEquals(VaultRouteMode.UNLOCK, viewModel.state.value.mode)
            assertEquals("Private vault", viewModel.state.value.selectedTitle)
            assertTrue(requireNotNull(viewModel.state.value.selectedLocation).isVaultRoot)
            viewModel.leaveRoute()
        }

    @Test
    fun directVaultEntryRejectsLocationFromAnotherAccount() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> error("Unlock is not used in this test.") })
            val viewModel = newViewModel(repository)

            viewModel.enterRoute(ACCOUNT, location.copy(accountId = "another-account"))
            runCurrent()

            assertEquals(0, repository.locationsCalls)
            assertEquals(VaultRouteMode.CATALOG, viewModel.state.value.mode)
            assertEquals(VaultRouteError.VAULT_CHANGED, viewModel.state.value.error)
            assertNull(viewModel.state.value.selectedLocation)
            viewModel.retry()
            assertEquals(0, repository.locationsCalls)
            viewModel.leaveRoute()
        }

    @Test
    fun successfulPasswordUnlockOffersBiometricsOnceAndDeclineIsRememberedPerIdentity() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val preferences = TestVaultOfferPreferences()
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> TestSession(identity, emptyList()) })
            val viewModel = newViewModel(repository, preferences)
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )

            viewModel.unlock("secret".toCharArray())
            advanceUntilIdle()

            assertTrue(viewModel.state.value.biometricOfferPending)
            viewModel.declineBiometricOffer()
            assertEquals(VaultPreferenceStatus.DECLINED, preferences.status(identity))
            assertEquals(false, viewModel.state.value.biometricOfferPending)

            viewModel.lock()
            advanceUntilIdle()
            viewModel.unlock("secret".toCharArray())
            advanceUntilIdle()

            assertEquals(false, viewModel.state.value.biometricOfferPending)
            viewModel.leaveRoute()
        }

    @Test
    fun firstPasswordUnlockWithFreshVerifiedKeyMaterialOffersEnrollment() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val viewModel =
                newViewModel(
                    TestRepository(unlockBlock = { _, _, _, _ -> TestSession(identity, emptyList()) }),
                    TestVaultOfferPreferences(),
                )
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )

            viewModel.unlock("secret".toCharArray())
            advanceUntilIdle()

            assertTrue(viewModel.state.value.biometricOfferPending)
            assertTrue(viewModel.state.value.canEnrollBiometric)
            viewModel.leaveRoute()
        }

    @Test
    fun acceptingOfferDismissesItForEnrollmentPrompt() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val viewModel =
                newViewModel(
                    TestRepository(unlockBlock = { _, _, _, _ -> TestSession(identity, emptyList()) }),
                    TestVaultOfferPreferences(),
                )
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )
            viewModel.unlock("secret".toCharArray())
            advanceUntilIdle()

            viewModel.acceptBiometricOffer()

            assertEquals(false, viewModel.state.value.biometricOfferPending)
            assertEquals(false, viewModel.state.value.biometricEnrolled)
            viewModel.leaveRoute()
        }

    @Test
    fun failureClassificationUsesNetworkAndServerSemanticsWithoutGuessingPassword() {
        assertEquals(
            VaultRouteError.CONNECTION,
            classifyVaultFailure(UnknownHostException(), VaultRouteError.UNLOCK),
        )
        assertEquals(
            VaultRouteError.SECURE_CONNECTION,
            classifyVaultFailure(OpenCloudException(OpenCloudError.Trust), VaultRouteError.UNLOCK),
        )
        assertEquals(
            VaultRouteError.AUTHENTICATION,
            classifyVaultFailure(OpenCloudException(OpenCloudError.AuthenticationRequired), VaultRouteError.UNLOCK),
        )
        assertEquals(
            VaultRouteError.AUTHENTICATION,
            classifyVaultFailure(OpenCloudException(OpenCloudError.ClientRegistrationRequired), VaultRouteError.UNLOCK),
        )
        assertEquals(
            VaultRouteError.ACCESS_DENIED,
            classifyVaultFailure(OpenCloudException(OpenCloudError.AccessDenied), VaultRouteError.UNLOCK),
        )
        assertEquals(
            VaultRouteError.SERVER_RESPONSE,
            classifyVaultFailure(OpenCloudException(OpenCloudError.InvalidResponse), VaultRouteError.CATALOG),
        )
        assertEquals(
            VaultRouteError.VAULT_CHANGED,
            classifyVaultFailure(OpenCloudException(OpenCloudError.NotFound), VaultRouteError.UNLOCK),
        )
        assertEquals(
            VaultRouteError.DISCOVERY,
            classifyVaultFailure(
                OpenCloudException(OpenCloudError.NotFound),
                VaultRouteError.DISCOVERY,
                classifyVaultIdentity = false,
            ),
        )
        assertEquals(
            VaultRouteError.UNLOCK_PROOF,
            classifyVaultFailure(
                VaultUnlockException(VaultUnlockFailure.PASSWORD_NOT_PROVEN),
                VaultRouteError.UNLOCK,
            ),
        )
    }

    @Test
    fun latePreviewAfterDismissIsWipedAndCannotRepublish() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            var pendingPreview: Continuation<ByteArray>? = null
            val session =
                TestSession(
                    identity = identity,
                    entries = listOf(folder("notes.txt")),
                    previewBlock = { suspendCoroutine { pendingPreview = it } },
                )
            val viewModel = newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> session }))
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )
            viewModel.unlock("secret".toCharArray())
            advanceUntilIdle()

            viewModel.openPreview(
                viewModel.state.value.entries
                    .single()
                    .id,
            )
            runCurrent()
            viewModel.dismissPreview()
            val lateBytes = "late plaintext".toByteArray()
            requireNotNull(pendingPreview).resume(lateBytes)
            advanceUntilIdle()

            assertNull(viewModel.state.value.preview)
            assertEquals(VaultRouteMode.CONTENTS, viewModel.state.value.mode)
            assertTrue(lateBytes.all { it == 0.toByte() })
            viewModel.leaveRoute()
        }

    @Test
    fun accessRevocationDuringPreviewLocksAndClearsListedNames() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val session =
                TestSession(
                    identity = identity,
                    entries = listOf(folder("private.txt")),
                    previewBlock = { throw OpenCloudException(OpenCloudError.AccessDenied) },
                )
            val viewModel = newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> session }))
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            viewModel.selectLocation(
                viewModel.state.value.locations
                    .single()
                    .id,
            )
            viewModel.unlock("secret".toCharArray())
            advanceUntilIdle()
            viewModel.openPreview(
                viewModel.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()

            assertEquals(VaultRouteMode.UNLOCK, viewModel.state.value.mode)
            assertEquals(VaultRouteError.ACCESS_DENIED, viewModel.state.value.error)
            assertTrue(
                viewModel.state.value.entries
                    .isEmpty(),
            )
            assertNull(viewModel.state.value.preview)
            assertTrue(session.closed)
            viewModel.leaveRoute()
        }

    @Test
    fun forgetWithStaleRevisionCannotDeleteAnotherTargetsEnrollment() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val locations = listOf(location, location.copy(remoteVaultId = "other-vault", title = "Other vault"))
            val store = TestBiometricStore()
            val viewModel =
                newViewModel(
                    TestRepository(
                        unlockBlock = { _, _, _, _ -> error("Unlock is not used in this test.") },
                        locations = locations,
                    ),
                    biometricStore = store,
                )
            viewModel.enterRoute(ACCOUNT)
            runCurrent()
            val presented = viewModel.state.value.locations
            viewModel.selectLocation(presented[0].id)
            val staleRevision = viewModel.state.value.lockRevision
            viewModel.selectLocation(presented[1].id)

            viewModel.forgetBiometric(staleRevision)

            assertTrue(store.forgottenIdentities.isEmpty())
            viewModel.leaveRoute()
        }

    @Test fun managementLeaseRejectsLockedOrReplacedTargets() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val model = newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> TestSession(identity, emptyList()) }))
            model.enterRoute(ACCOUNT)
            advanceUntilIdle()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("synthetic".toCharArray())
            advanceUntilIdle()
            val revision = model.state.value.lockRevision
            val managed = requireNotNull(model.managementTarget(revision))
            assertTrue(model.isManagementUnlocked(managed, revision))
            assertEquals(false, model.isManagementUnlocked(managed.copy(accountId = "other"), revision))
            assertEquals(false, model.isManagementUnlocked(managed.copy(remoteVaultId = "replaced"), revision))
            model.managedSpaceChanged(managed.copy(title = "Renamed Space"), revision)
            assertEquals("Renamed Space", model.state.value.selectedTitle)
            model.lock()
            assertEquals(false, model.isManagementUnlocked(managed, revision))
            model.managedSpaceChanged(managed.copy(title = "Stale name"), revision)
            assertEquals("Renamed Space", model.state.value.selectedTitle)
            model.leaveRoute()
        }

    internal fun newViewModel(
        repository: TestRepository,
        preferences: VaultOfferPreferences = TestVaultOfferPreferences(),
        biometricStore: VaultBiometricKeyStore = TestBiometricStore(),
    ) = VaultViewModel(
        ApplicationProvider.getApplicationContext<Application>(),
        repository,
        biometricStore,
        preferences,
        ioDispatcher = Dispatchers.Main,
        adapters =
            VaultViewModelAdapters(
                ApplicationProvider.getApplicationContext<Application>(),
                deviceRemember = UnsupportedDeviceRememberAccess,
            ),
    )

    private object UnsupportedDeviceRememberAccess : VaultDeviceRememberAccess {
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

    private class TestVaultOfferPreferences : VaultOfferPreferences {
        private val values = mutableMapOf<VaultIdentity, VaultPreferenceStatus>()

        override fun status(identity: VaultIdentity) = values[identity]

        override fun remember(
            identity: VaultIdentity,
            title: String,
            targetKind: VaultPreferenceTargetKind,
        ) {
            values[identity] = VaultPreferenceStatus.REMEMBERED
        }

        override fun decline(
            identity: VaultIdentity,
            title: String,
            targetKind: VaultPreferenceTargetKind,
        ) {
            values[identity] = VaultPreferenceStatus.DECLINED
        }

        override fun remove(identity: VaultIdentity) {
            values.remove(identity)
        }
    }

    internal class TestRepository(
        private val unlockBlock: suspend (String, VaultLocation, String, CharArray) -> VaultRouteSession,
        private val locations: List<VaultLocation> = listOf(location),
        private val foldersBlock: (String) -> List<VaultFolder> = { emptyList() },
    ) : VaultRouteRepository {
        var locationsCalls = 0

        override suspend fun locations(accountId: String): List<VaultLocation> {
            locationsCalls += 1
            return locations
        }

        override suspend fun folders(
            accountId: String,
            location: VaultLocation,
            path: String,
        ) = foldersBlock(path)

        override suspend fun unlock(
            accountId: String,
            target: VaultLocation,
            vaultPath: String,
            password: CharArray,
        ) = unlockBlock(accountId, target, vaultPath, password)

        override suspend fun unlockWithKeyMaterial(
            accountId: String,
            target: VaultLocation,
            vaultPath: String,
            keyMaterial: ByteArray,
        ): VaultRouteSession = error("Biometric unlock is not used in this test.")
    }

    @Suppress("LongParameterList") // Explicit session behaviors let each lock/import race vary independently.
    internal class TestSession(
        override val identity: VaultIdentity,
        private val entries: List<VaultFolder>,
        private val exportBlock: suspend () -> ByteArray = { ByteArray(80) },
        private val previewBlock: suspend (VaultFolder) -> ByteArray = { error("Preview is not used in this test.") },
        private val offlineBlock: (suspend () -> Unit)? = null,
        private val offlineStatus: () -> Boolean? = { null },
        private val pendingOfflineIds: Flow<String?>? = null,
        override val isOffline: Boolean = false,
    ) : VaultRouteSession {
        var closed = false
        var listCalls = 0

        override fun offlineAvailable(entry: VaultFolder): Boolean? = offlineStatus()

        override suspend fun list(path: String): List<VaultFolder> {
            listCalls += 1
            return entries
        }

        override suspend fun preview(entry: VaultFolder) = previewBlock(entry)

        override suspend fun exportVerifiedKeyMaterial() = exportBlock()

        override fun observePendingOffline(): Flow<Unit> =
            // Unlock now performs the initial recovery pass. Explicit IDs model subsequent queue changes.
            pendingOfflineIds?.pendingOfflineCompletionEvents() ?: kotlinx.coroutines.flow.emptyFlow()

        override suspend fun completePendingOffline() {
            offlineBlock?.invoke()
        }

        override fun close() {
            closed = true
        }
    }

    private class TestBiometricStore : VaultBiometricKeyStore {
        val forgottenIdentities = mutableListOf<VaultIdentity>()

        override fun hasEnrollment(identity: VaultIdentity) = false

        override fun prepareEnrollment(identity: VaultIdentity): Cipher = error("Not used in test.")

        override fun completeEnrollment(
            identity: VaultIdentity,
            cipher: Cipher,
            keyMaterial: ByteArray,
        ) = Unit

        override fun cancelEnrollment(identity: VaultIdentity) = Unit

        override fun prepareUnlock(identity: VaultIdentity): Cipher = error("Not used in test.")

        override fun completeUnlock(
            identity: VaultIdentity,
            cipher: Cipher,
        ): ByteArray = error("Not used in test.")

        override fun cancelUnlock(identity: VaultIdentity) = Unit

        override fun forget(identity: VaultIdentity) {
            forgottenIdentities += identity
        }
    }

    internal fun folder(name: String) =
        VaultFolder(
            id = name,
            name = name,
            rawName = name,
            path = name,
            encryptedPath = name,
            isFolder = false,
            size = name.length.toLong(),
            strongETag = null,
        )

    companion object {
        internal const val ACCOUNT = "account"
        internal val identity = VaultIdentity(ACCOUNT, "https://cloud.example", "drive", "vault-root")
        internal val location =
            VaultLocation(
                accountId = ACCOUNT,
                title = "Private vault",
                kind = VaultLocationKind.FOLDER_VAULT,
                driveId = identity.driveId,
                remoteVaultId = identity.remoteVaultId,
                sourceRootId = "source-root",
                canonicalServer = identity.canonicalServer,
                rootWebDavUrl = "https://cloud.example/dav/root",
                vaultPath = "",
                isVaultRoot = true,
            )
    }
}
