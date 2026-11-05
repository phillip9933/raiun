package eu.opencloud.android.next.core.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/** Real record/ledger IO and AES/GCM; the injected provider is software, not Android Keystore. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VaultRememberRestoreTimingTest {
    @get:Rule val temporaryFolder = TemporaryFolder()

    @Test fun fileBackedRestoreAndRepeatedAdmissionKeepRevocationAndZeroization() {
        val directory = temporaryFolder.newFolder("restore-timing")
        val crypto = SoftwareProvider()
        val identity = VaultIdentity("synthetic-account", "https://synthetic.example", "drive", "vault")
        val binding = VaultRememberBinding("a".repeat(32), "b".repeat(64))
        val material = ByteArray(80) { it.toByte() }

        fun store() = VaultDeviceRememberStore(directory, crypto, { false }, { true }, { true })
        val writer = store()
        try {
            assertTrue(
                writer.remember(requireNotNull(writer.begin(identity, binding)), identity, binding, material) { true },
            )
            // One warmup, then three bounded samples. No elapsed-time pass/fail thresholds.
            repeat(4) { sample ->
                var permit = true
                val reader = store()
                val loadsBefore = crypto.loads
                val started = System.nanoTime()
                val key = requireNotNull(reader.restore(identity, binding) { permit })
                val restored = System.nanoTime()
                try {
                    assertArrayEquals(material, key.material)
                    repeat(6) { assertTrue(key.isCurrent()) }
                    val admitted = System.nanoTime()
                    assertEquals("Currency checks must not decrypt the envelope again.", loadsBefore + 1, crypto.loads)
                    if (sample > 0) {
                        println("VAULT_TIMING software_disk_restore sample=$sample elapsed_ns=${restored - started}")
                        println(
                            "VAULT_TIMING software_disk_currency_checks sample=$sample elapsed_ns=${admitted - restored}",
                        )
                    }
                    permit = false
                    assertFalse("Fresh credential revocation must still be observed.", key.isCurrent())
                } finally {
                    key.close()
                    assertArrayEquals(ByteArray(80), key.material)
                }
            }
            val restored = requireNotNull(store().restore(identity, binding) { true })
            try {
                // A different store instance must revoke an already issued key without a cache delay.
                store().forget(identity)
                assertFalse(restored.isCurrent())
            } finally {
                restored.close()
                assertArrayEquals(ByteArray(80), restored.material)
            }
        } finally {
            material.fill(0)
            writer.forget(identity)
        }
    }

    private class SoftwareProvider : VaultDeviceRememberCrypto {
        private val keys = mutableMapOf<String, SecretKey>()
        var loads = 0
            private set

        override fun isPlatformSupported() = true

        override fun create(alias: String): SecretKey =
            SecretKeySpec(ByteArray(32) { 7 }, "AES").also { keys[alias] = it }

        override fun load(alias: String): SecretKey? {
            loads++
            return keys[alias]
        }

        override fun aliases() = keys.keys.toSet()

        override fun delete(alias: String) {
            keys.remove(alias)
        }

        override fun isAcceptable(key: SecretKey) = keys.values.any { it === key }
    }
}
