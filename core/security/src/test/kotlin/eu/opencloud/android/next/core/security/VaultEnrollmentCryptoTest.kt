package eu.opencloud.android.next.core.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.AlgorithmParameters
import java.security.Key
import java.security.MessageDigest
import java.security.Provider
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.Cipher
import javax.crypto.CipherSpi
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.spec.GCMParameterSpec

class VaultEnrollmentCryptoTest {
    @get:Rule val temporaryFolder = TemporaryFolder()

    @Test
    fun envelopeUsesTheNonceCapturedBeforeAuthenticatedFinalization() {
        val identity = VaultIdentity("account", "https://cloud.example", "drive", "vault")
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val encryptor = Cipher.getInstance("AES/GCM/NoPadding")
        encryptor.init(Cipher.ENCRYPT_MODE, key)
        val preparedNonce = requireNotNull(encryptor.iv).copyOf()
        val keyMaterial = ByteArray(80) { (it + 1).toByte() }

        val envelope = VaultKeyEnvelopeCrypto.seal(identity, "test-alias", preparedNonce, encryptor, keyMaterial)

        assertArrayEquals(preparedNonce, envelope.nonce)
        val decryptor = Cipher.getInstance("AES/GCM/NoPadding")
        decryptor.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.nonce))
        assertArrayEquals(keyMaterial, VaultKeyEnvelopeCrypto.unwrap(identity, decryptor, envelope.ciphertext))

        preparedNonce.fill(0)
        keyMaterial.fill(0)
        envelope.identity.fill(0)
        envelope.nonce.fill(0)
        envelope.ciphertext.fill(0)
    }

    @Test
    fun authenticatedCompletionFeedsAadOnlyAfterThePromptAuthorizesTheCipher() {
        val identity = VaultIdentity("account", "https://cloud.example", "drive", "vault")
        val material = ByteArray(80) { it.toByte() }
        val encryptSpi = AuthGateCipherSpi()
        val encrypt = AuthGateCipher(encryptSpi)
        encrypt.init(Cipher.ENCRYPT_MODE, KeyGenerator.getInstance("AES").generateKey())
        // An updateAAD here would poison the operation and cause doFinal to fail, as on Keystore2.
        encryptSpi.authorized = true
        val record = VaultKeyEnvelopeCrypto.seal(identity, "test-alias", ByteArray(12), encrypt, material)
        assertArrayEquals(identity.associatedData, encryptSpi.aad)

        val decryptSpi = AuthGateCipherSpi()
        val decrypt = AuthGateCipher(decryptSpi)
        decrypt.init(Cipher.DECRYPT_MODE, KeyGenerator.getInstance("AES").generateKey())
        decryptSpi.authorized = true
        assertArrayEquals(material, VaultKeyEnvelopeCrypto.unwrap(identity, decrypt, record.ciphertext))
        assertArrayEquals(identity.associatedData, decryptSpi.aad)

        val earlySpi = AuthGateCipherSpi()
        val early = AuthGateCipher(earlySpi)
        early.init(Cipher.ENCRYPT_MODE, KeyGenerator.getInstance("AES").generateKey())
        early.updateAAD(identity.associatedData)
        earlySpi.authorized = true
        assertThrows(IllegalBlockSizeException::class.java) {
            VaultKeyEnvelopeCrypto.seal(identity, "test-alias", ByteArray(12), early, material)
        }
        material.fill(0)
        record.identity.fill(0)
        record.nonce.fill(0)
        record.ciphertext.fill(0)
    }

    @Test
    fun inventoryListsValidKeyEnvelopesWithoutPreferenceMetadata() {
        val identity = VaultIdentity("account", "https://cloud.example", "drive", "vault")
        val identityBytes = identity.encoded
        val identityHash = identityBytes.sha256Hex()
        val accountHash = "account".toByteArray().sha256Hex().take(32)
        val record =
            VaultEnvelope(
                identityBytes,
                "raiun_vault_v2_${accountHash}_${identityHash}_test",
                ByteArray(12) { 1 },
                ByteArray(96) { 2 },
            )
        val directory = temporaryFolder.newFolder("vault-key-envelopes")
        File(directory, "$identityHash.envelope").writeBytes(VaultEnvelopeCodec.encode(record))

        assertEquals(listOf(identity), VaultAccountEnvelopeInventory.identities(directory))

        identityBytes.fill(0)
        record.identity.fill(0)
        record.nonce.fill(0)
        record.ciphertext.fill(0)
    }

    private fun ByteArray.sha256Hex() =
        MessageDigest.getInstance("SHA-256").digest(this).joinToString("") { "%02x".format(it) }
}

/** Mimics Keystore2 caching an auth error from AAD and reporting it only at finalization. */
private class AuthGateCipherSpi : CipherSpi() {
    var authorized = false
    var aad: ByteArray? = null
    private var poisoned = false
    private var mode = Cipher.ENCRYPT_MODE

    override fun engineSetMode(mode: String?) = Unit

    override fun engineSetPadding(padding: String?) = Unit

    override fun engineGetBlockSize() = 16

    override fun engineGetOutputSize(inputLen: Int) = inputLen + 16

    override fun engineGetIV(): ByteArray = ByteArray(12)

    override fun engineGetParameters(): AlgorithmParameters? = null

    override fun engineInit(
        opmode: Int,
        key: Key?,
        random: SecureRandom?,
    ) {
        mode = opmode
    }

    override fun engineInit(
        opmode: Int,
        key: Key?,
        params: AlgorithmParameterSpec?,
        random: SecureRandom?,
    ) {
        mode = opmode
    }

    override fun engineInit(
        opmode: Int,
        key: Key?,
        params: AlgorithmParameters?,
        random: SecureRandom?,
    ) {
        mode = opmode
    }

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
    ): ByteArray = input.copyOfRange(inputOffset, inputOffset + inputLen)

    override fun engineUpdate(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int,
    ): Int {
        input.copyInto(output, outputOffset, inputOffset, inputOffset + inputLen)
        return inputLen
    }

    override fun engineUpdateAAD(
        src: ByteArray,
        offset: Int,
        len: Int,
    ) {
        if (!authorized) poisoned = true else aad = src.copyOfRange(offset, offset + len)
    }

    override fun engineDoFinal(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
    ): ByteArray {
        if (poisoned || !authorized) throw IllegalBlockSizeException("authorization was cached")
        check(aad != null)
        val bytes = input.copyOfRange(inputOffset, inputOffset + inputLen)
        return if (mode == Cipher.ENCRYPT_MODE) bytes + ByteArray(16) else bytes.copyOfRange(0, bytes.size - 16)
    }

    override fun engineDoFinal(
        input: ByteArray,
        inputOffset: Int,
        inputLen: Int,
        output: ByteArray,
        outputOffset: Int,
    ): Int {
        val bytes = engineDoFinal(input, inputOffset, inputLen)
        bytes.copyInto(output, outputOffset)
        return bytes.size
    }
}

private class AuthGateCipher(
    spi: AuthGateCipherSpi,
) : Cipher(spi, object : Provider("RaiunAuthGateTest", 1.0, "test") {}, "AES/GCM/NoPadding")
