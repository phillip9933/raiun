package eu.opencloud.android.next.core.security

import android.app.KeyguardManager
import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/** Real provider smoke for the Android 15+ key policy; no account or vault data is used. */
@RunWith(AndroidJUnit4::class)
class VaultDeviceRememberKeyAndroidTest {
    @Test fun androidBefore15ReportsUnsupportedWithoutGeneratingAKey() {
        assumeTrue("This fallback assertion is for Android versions before 15.", Build.VERSION.SDK_INT < 35)
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertFalse(VaultDeviceRememberStore(context).isSupported())
    }

    @Test fun androidBefore15CredentialAndStrictPolicyHooksRemainAvailable() {
        assumeTrue(
            "The credential-hook fallback assertion is for Android versions before 15.",
            Build.VERSION.SDK_INT < 35,
        )
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val accountId = "device-remember-test-${java.util.UUID.randomUUID()}"
        val identity = VaultIdentity(accountId, "https://synthetic.example", "drive", "vault")
        val store = VaultDeviceRememberStore(context)
        val credentials = KeystoreCredentialStore(context)
        val policy = VaultUnlockPolicy(context)
        try {
            policy.setAskEveryTime(false)
            store.decline(identity)
            assertEquals(VaultRememberChoice.DECLINED, store.choice(identity))
            policy.setAskEveryTime(true)
            assertEquals(
                "Strict mode preserves the explicit declined choice.",
                VaultRememberChoice.DECLINED,
                store.choice(identity),
            )
            assertTrue(policy.askEveryTime())

            policy.setAskEveryTime(false)
            credentials.saveBasicUsername(accountId, "synthetic-test-user")
            assertEquals("synthetic-test-user", credentials.readBasicUsername(accountId))
            assertNull(store.choice(identity))
            assertFalse(store.isSupported())
        } finally {
            policy.setAskEveryTime(false)
            credentials.remove(accountId)
            store.forget(identity)
        }
    }

    @Test fun android15OrNewerCreatesHardwareAesKeyWithUnlockedDevicePolicy() {
        assumeTrue("Unlocked-device-required policy is supported from Android 15.", Build.VERSION.SDK_INT >= 35)
        val crypto = AndroidVaultDeviceRememberCrypto()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        assumeTrue(
            "Run this provider operation while a secure phone is unlocked.",
            keyguard?.isDeviceSecure == true && keyguard?.isDeviceLocked == false,
        )
        val random = SecureRandom()
        val alias = "raiun_vault_device_v1_${ByteArray(
            32,
        ).also(random::nextBytes).hex()}_${ByteArray(8).also(random::nextBytes).hex()}"
        val plaintext = ByteArray(80).also(random::nextBytes)
        try {
            val key = crypto.create(alias)
            assertTrue("Key must meet hardware AES/GCM policy checks.", crypto.isAcceptable(key))
            val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
            val ciphertext = encrypt.doFinal(plaintext)
            val decrypt =
                Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(Cipher.DECRYPT_MODE, requireNotNull(crypto.load(alias)), GCMParameterSpec(128, encrypt.iv))
                }
            assertArrayEquals(plaintext, decrypt.doFinal(ciphertext))
            ciphertext.fill(0)
        } finally {
            plaintext.fill(0)
            crypto.delete(alias)
        }
    }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }
}
