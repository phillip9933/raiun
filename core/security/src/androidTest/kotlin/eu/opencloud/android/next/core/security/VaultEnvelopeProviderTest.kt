package eu.opencloud.android.next.core.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

/** Actual Android provider envelope check; this deliberately does not claim biometric authentication coverage. */
@RunWith(AndroidJUnit4::class)
class VaultEnvelopeProviderTest {
    @Test fun capturedNonceSealsAndReopensKeyMaterialWithAndroidKeystore() {
        val alias = "raiun_synthetic_nonce_${UUID.randomUUID()}"
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val identity = VaultIdentity("synthetic-account", "https://cloud.example", "drive", "root")
        val material = ByteArray(80) { it.toByte() }
        try {
            val key =
                KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                    .apply {
                        init(
                            KeyGenParameterSpec
                                .Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setKeySize(256)
                                .build(),
                        )
                    }.generateKey()
            val encrypt =
                Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(Cipher.ENCRYPT_MODE, key)
                }
            val capturedNonce = requireNotNull(encrypt.iv).copyOf()
            val record = VaultKeyEnvelopeCrypto.seal(identity, alias, capturedNonce, encrypt, material)
            try {
                assertArrayEquals(capturedNonce, record.nonce)
                val decrypt =
                    Cipher.getInstance("AES/GCM/NoPadding").apply {
                        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, record.nonce))
                    }
                val opened = VaultKeyEnvelopeCrypto.unwrap(identity, decrypt, record.ciphertext)
                try {
                    assertArrayEquals(material, opened)
                } finally {
                    opened.fill(0)
                }
            } finally {
                capturedNonce.fill(0)
                record.nonce.fill(0)
                record.identity.fill(0)
                record.ciphertext.fill(0)
            }
        } finally {
            material.fill(0)
            if (store.containsAlias(alias)) store.deleteEntry(alias)
        }
    }
}
