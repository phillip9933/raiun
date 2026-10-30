package eu.opencloud.android.next.core.security

import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
class VaultUnlockPolicyTest {
    @get:Rule val temporaryFolder = TemporaryFolder()
    private val context: Context get() = RuntimeEnvironment.getApplication()
    private val identity = VaultIdentity("account", "https://cloud.example", "drive", "vault")
    private val binding = VaultRememberBinding("0123456789abcdef0123456789abcdef", "a".repeat(64))

    @Before fun prepareSecureUnlockedPhone() {
        context
            .getSharedPreferences("vault-unlock-policy", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
        VaultUnlockSession(context).clear()
        Shadows.shadowOf(context.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        Shadows.shadowOf(context.getSystemService(KeyguardManager::class.java)).setIsDeviceLocked(false)
        Shadows.shadowOf(context.getSystemService(PowerManager::class.java)).setIsInteractive(true)
    }

    @After fun clear() {
        VaultUnlockSession(context).clear()
        context
            .getSharedPreferences("vault-unlock-policy", Context.MODE_PRIVATE)
            .edit()
            .clear()
            .commit()
    }

    @Test fun defaultAndPolicyChangesClearProcessKeysWithoutPersistingThem() {
        val crypto = VaultDeviceRememberStoreTest.FakeCrypto()
        val directory = temporaryFolder.newFolder("remember-policy")
        val durableStore =
            VaultDeviceRememberStore(
                directory,
                crypto,
                {
                    context
                        .getSharedPreferences("vault-unlock-policy", Context.MODE_PRIVATE)
                        .getBoolean("ask-every-time", false)
                },
                { true },
                { true },
            )
        val policy = VaultUnlockPolicy(context) { value, commit -> durableStore.changeAskEveryTime(value, commit) }
        val session = VaultUnlockSession(context)
        assertFalse(policy.askEveryTime())
        val durableGrant = requireNotNull(durableStore.begin(identity, binding))
        assertTrue(durableStore.remember(durableGrant, identity, binding, ByteArray(80)) { true })
        val grant = session.beginUnlock()
        session.remember(grant, identity, "row", ByteArray(80)) { true }
        assertNotNull(session.reuse(identity, "row")?.also { it.close() })
        policy.setAskEveryTime(true)
        assertTrue(VaultUnlockPolicy(context).askEveryTime())
        assertFalse(durableStore.hasRemembered(identity))
        assertNull(session.beginUnlock())
        policy.setAskEveryTime(false)
        session.remember(grant, identity, "row", ByteArray(80)) { true }
        assertNull(session.reuse(identity, "row"))
        assertTrue(
            context
                .getSharedPreferences("vault-unlock-policy", Context.MODE_PRIVATE)
                .all.values
                .all { it is Boolean },
        )
        durableStore.forgetAll()
    }

    @Test fun screenOffGlobalAppLockRevokesKeysWhileNoRouteExists() {
        val session = VaultUnlockSession(context)
        val grant = session.beginUnlock()
        session.remember(grant, identity, "row", ByteArray(80)) { true }
        AppLock(context).lock() // The application-global ACTION_SCREEN_OFF receiver calls this entry point.
        session.remember(grant, identity, "row", ByteArray(80)) { true }
        assertNull(session.reuse(identity, "row"))
    }

    @Test fun noSecureLockLockedDeviceAndSleepingDisplayFailClosed() {
        val session = VaultUnlockSession(context)
        val keyguard = Shadows.shadowOf(context.getSystemService(KeyguardManager::class.java))
        keyguard.setIsDeviceSecure(false)
        assertNull(session.beginUnlock())
        keyguard.setIsDeviceSecure(true)
        keyguard.setIsDeviceLocked(true)
        assertNull(session.beginUnlock())
        keyguard.setIsDeviceLocked(false)
        Shadows.shadowOf(context.getSystemService(PowerManager::class.java)).setIsInteractive(false)
        assertNull(session.beginUnlock())
    }

    @Test fun malformedPolicyFailsClosed() {
        context
            .getSharedPreferences(
                "vault-unlock-policy",
                Context.MODE_PRIVATE,
            ).edit()
            .putString("ask-every-time", "invalid")
            .commit()
        assertTrue(VaultUnlockPolicy(context).askEveryTime())
        assertNull(VaultUnlockSession(context).beginUnlock())
    }
}
