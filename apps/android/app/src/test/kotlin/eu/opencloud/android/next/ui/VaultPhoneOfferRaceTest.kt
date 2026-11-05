package eu.opencloud.android.next.ui

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultRememberChoice
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.ACCOUNT
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.Companion.identity
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.TestBiometricStore
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.TestRepository
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.TestSession
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.TestVaultOfferPreferences
import eu.opencloud.android.next.ui.VaultViewModelRaceTest.UnsupportedDeviceRememberAccess
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import kotlin.coroutines.Continuation
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultPhoneOfferRaceTest {
    private val fixtures = VaultViewModelRaceTest()

    @After fun resetMain() = Dispatchers.resetMain()

    @Test
    fun oldPhoneOfferLookupAfterReentryCannotReplaceNewSessionOrRetainMaterial() =
        runTest {
            Dispatchers.setMain(StandardTestDispatcher(testScheduler))
            val io = QueuedDispatcher()
            var export: Continuation<ByteArray>? = null
            val material = ByteArray(80) { 0x5A }
            val old =
                TestSession(identity, listOf(fixtures.folder("old")), exportBlock = {
                    suspendCoroutine {
                        export =
                            it
                    }
                })
            val replacement = TestSession(identity, listOf(fixtures.folder("replacement")))
            var unlocks = 0
            var choices = 0
            val deviceRemember =
                object : VaultDeviceRememberAccess by UnsupportedDeviceRememberAccess {
                    override fun choice(identity: VaultIdentity): VaultRememberChoice? {
                        choices++
                        return null
                    }
                }
            val repository = TestRepository(unlockBlock = { _, _, _, _ -> if (unlocks++ == 0) old else replacement })
            val application = ApplicationProvider.getApplicationContext<Application>()
            val model =
                VaultViewModel(
                    application,
                    repository,
                    TestBiometricStore(),
                    TestVaultOfferPreferences(),
                    ioDispatcher = io,
                    adapters = VaultViewModelAdapters(application, deviceRemember = deviceRemember),
                )
            model.enterRoute(ACCOUNT)
            repeat(10) {
                io.runCurrent()
                runCurrent()
            }
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            repeat(10) {
                io.runCurrent()
                runCurrent()
            }
            model.unlock("secret".toCharArray())
            repeat(10) {
                io.runCurrent()
                runCurrent()
            }
            requireNotNull(export).resume(material)
            // Stop after the IO-side offer lookup, before its continuation runs on Main.
            repeat(20) {
                if (choices == 0) {
                    runCurrent()
                    io.runCurrent()
                }
            }
            assertEquals(1, choices)
            model.lock()
            model.leaveRoute()
            model.enterRoute(ACCOUNT)
            repeat(10) {
                io.runCurrent()
                runCurrent()
            }
            model.selectLocation(
                model.state.value.locations
                    .single()
                    .id,
            )
            repeat(10) {
                io.runCurrent()
                runCurrent()
            }
            model.unlock("secret".toCharArray())
            repeat(20) {
                io.runCurrent()
                runCurrent()
            }

            assertTrue(old.closed)
            assertTrue(material.all { it == 0.toByte() })
            assertTrue(!replacement.closed)
            assertEquals(
                listOf("replacement"),
                model.state.value.entries
                    .map { it.name },
            )
            model.leaveRoute()
        }

    private class QueuedDispatcher : CoroutineDispatcher() {
        private val tasks = ArrayDeque<Runnable>()

        override fun dispatch(
            context: CoroutineContext,
            block: Runnable,
        ) {
            tasks.addLast(block)
        }

        fun runCurrent() {
            while (tasks.isNotEmpty()) tasks.removeFirst().run()
        }
    }
}
