package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.ACCOUNT
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.identity
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.location
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.TestRepository
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.TestSession
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
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

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultNavigationTest {
    private val fixtures = VaultViewModelRaceTest()

    @After
    fun resetMainDispatcher() {
        Dispatchers.resetMain()
    }

    @Test fun `back navigates nested folders then closes root session to catalog`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val opened = TestSession(identity, listOf(fixtures.folder("nested").copy(isFolder = true)))
            val model = fixtures.newViewModel(TestRepository(unlockBlock = { _, _, _, _ -> opened }))
            model.enterRoute(ACCOUNT)
            advanceUntilIdle()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            model.unlock("secret".toCharArray())
            advanceUntilIdle()
            model.openVaultFolder(
                model.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()
            navigateVaultBack(model.state.value, model) { error("Catalog owns this navigation") }
            advanceUntilIdle()
            assertEquals(VaultRouteMode.CONTENTS, model.state.value.mode)
            assertEquals("", model.state.value.currentPath)
            assertTrue(!opened.closed)
            navigateVaultBack(model.state.value, model) { error("Catalog owns this navigation") }
            assertEquals(VaultRouteMode.CATALOG, model.state.value.mode)
            assertTrue(opened.closed)
            assertNull(model.prepareBiometricUnlock())
            model.leaveRoute()
        }

    @Test fun `back restores discovery parent after encrypted folder unlock and explicit lock`() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val source = location.copy(isVaultRoot = false, kind = VaultLocationKind.PERSONAL)
            val opened = TestSession(identity, emptyList())
            val repository =
                TestRepository(
                    unlockBlock = { _, _, _, _ -> opened },
                    locations = listOf(source),
                    foldersBlock = { path ->
                        if (path.isEmpty()) {
                            listOf(fixtures.folder("parent").copy(isFolder = true))
                        } else {
                            listOf(
                                fixtures
                                    .folder(
                                        "secret",
                                    ).copy(path = "parent/secret", isFolder = true, isVaultRoot = true),
                            )
                        }
                    },
                )
            val model = fixtures.newViewModel(repository)
            model.enterRoute(ACCOUNT)
            advanceUntilIdle()
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            advanceUntilIdle()
            model.openDiscoveryFolder(
                model.state.value.entries
                    .single()
                    .id,
            )
            advanceUntilIdle()
            model.selectVaultFolder(
                model.state.value.entries
                    .single()
                    .id,
            )
            model.unlock("secret".toCharArray())
            advanceUntilIdle()
            model.lock()
            navigateVaultBack(model.state.value, model) { error("Discovery owns this navigation") }
            advanceUntilIdle()
            assertEquals(VaultRouteMode.DISCOVERY, model.state.value.mode)
            assertEquals("parent", model.state.value.currentPath)
            assertEquals("parent", model.state.value.browseTitle)
            assertTrue(opened.closed)
            assertNull(model.prepareBiometricUnlock())
            model.leaveRoute()
        }

    @Test fun `biometric unlock skips extra confirmation but retains strong authentication`() {
        val prompt = biometricPromptInfo("Vault", "Unlock", "Cancel", confirmationRequired = false)
        assertTrue(!prompt.isConfirmationRequired)
        assertEquals(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG, prompt.allowedAuthenticators)
        assertTrue(biometricPromptInfo("Vault", "Enroll", "Cancel").isConfirmationRequired)
    }
}
