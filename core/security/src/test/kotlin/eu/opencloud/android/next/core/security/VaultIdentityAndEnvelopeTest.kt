package eu.opencloud.android.next.core.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class VaultIdentityAndEnvelopeTest {
    @get:Rule val temp = TemporaryFolder()

    @Test
    fun accountInventorySelectsOnlyItsEnvelopesAndAcceptsLegacyAlias() {
        val directory = temp.newFolder("vault-key-envelopes")
        val first = sampleIdentity(accountId = "first-account")
        val second = sampleIdentity(accountId = "second-account")
        val firstKey = writeEnvelopeFile(directory, first, accountTagged = true)
        val secondKey = writeEnvelopeFile(directory, second, accountTagged = false)

        assertEquals(setOf(firstKey), VaultAccountEnvelopeInventory.keysForAccount(directory, first.accountId))
        assertEquals(setOf(secondKey), VaultAccountEnvelopeInventory.keysForAccount(directory, second.accountId))
        assertEquals(2, directory.listFiles()?.size)
    }

    @Test
    fun accountInventoryFailsClosedOnUnattributableRecord() {
        val directory = temp.newFolder("vault-key-envelopes")
        writeEnvelopeFile(directory, sampleIdentity(accountId = "first-account"), accountTagged = true)
        File(directory, "0".repeat(64) + ".envelope.bak").writeText("corrupt")

        assertThrows(VaultEnvelopeException::class.java) {
            VaultAccountEnvelopeInventory.keysForAccount(directory, "first-account")
        }
    }

    @Test
    fun accountInventoryRejectsAliasClaimingAnotherAccount() {
        val directory = temp.newFolder("vault-key-envelopes")
        val identity = sampleIdentity(accountId = "first-account")
        val key = MessageDigest.getInstance("SHA-256").digest(identity.encoded).toHexForTest()
        val otherHash =
            MessageDigest
                .getInstance("SHA-256")
                .digest("second-account".toByteArray(Charsets.UTF_8))
                .toHexForTest()
                .take(32)
        val record =
            VaultEnvelope(
                identity.encoded,
                "raiun_vault_v2_${otherHash}_${key}_" + "0".repeat(32),
                ByteArray(12),
                ByteArray(96),
            )
        File(directory, "$key.envelope").writeBytes(VaultEnvelopeCodec.encode(record))

        assertThrows(VaultEnvelopeException::class.java) {
            VaultAccountEnvelopeInventory.keysForAccount(directory, identity.accountId)
        }
    }

    @Test
    fun identityEncodingIsStableAndScopesEveryRemoteIdentityPart() {
        val identity = sampleIdentity()

        assertArrayEquals(identity.associatedData, sampleIdentity().associatedData)
        assertNotEquals(
            identity.associatedData.toList(),
            sampleIdentity(driveId = "other-drive").associatedData.toList(),
        )
        assertNotEquals(
            identity.associatedData.toList(),
            sampleIdentity(remoteVaultId = "other-vault").associatedData.toList(),
        )
        assertNotEquals(
            identity.associatedData.toList(),
            sampleIdentity(accountId = "other-account").associatedData.toList(),
        )
        assertNotEquals(
            identity.associatedData.toList(),
            sampleIdentity(canonicalServer = "https://other.example").associatedData.toList(),
        )
    }

    @Test
    fun lengthPrefixingAvoidsDelimiterAmbiguity() {
        val first = VaultIdentity("account|server", "https://host", "drive", "vault")
        val second = VaultIdentity("account", "server|https://host", "drive", "vault")

        assertNotEquals(first.encoded.toList(), second.encoded.toList())
        assertNotEquals(first.associatedData.toList(), second.associatedData.toList())
    }

    @Test
    fun identityRejectsBlankTrimmedAndOversizedFields() {
        assertThrows(IllegalArgumentException::class.java) {
            VaultIdentity("account", "https://host", " ", "vault").encoded
        }
        assertThrows(IllegalArgumentException::class.java) {
            VaultIdentity(" account", "https://host", "drive", "vault").encoded
        }
        assertThrows(IllegalArgumentException::class.java) {
            VaultIdentity("a".repeat(4097), "https://host", "drive", "vault").encoded
        }
    }

    @Test
    fun envelopeRoundTripsWithBoundedOpaqueFields() {
        val identity = sampleIdentity().encoded
        val envelope =
            VaultEnvelope(
                identity = identity,
                alias = "raiun_vault_v1_" + "a".repeat(64) + "_" + "b".repeat(32),
                nonce = ByteArray(12) { it.toByte() },
                ciphertext = ByteArray(96) { (it * 3).toByte() },
            )

        val decoded = VaultEnvelopeCodec.decode(VaultEnvelopeCodec.encode(envelope), identity)

        assertArrayEquals(envelope.identity, decoded.identity)
        assertEquals(envelope.alias, decoded.alias)
        assertArrayEquals(envelope.nonce, decoded.nonce)
        assertArrayEquals(envelope.ciphertext, decoded.ciphertext)
    }

    @Test
    fun envelopeRejectsWrongIdentityTrailingDataAndOutOfBoundsLengths() {
        val identity = sampleIdentity().encoded
        val envelope =
            VaultEnvelope(
                identity = identity,
                alias = "raiun_vault_v1_" + "a".repeat(64) + "_" + "b".repeat(32),
                nonce = ByteArray(12),
                ciphertext = ByteArray(96),
            )
        val encoded = VaultEnvelopeCodec.encode(envelope)

        assertThrows(IllegalArgumentException::class.java) {
            VaultEnvelopeCodec.decode(encoded, sampleIdentity(remoteVaultId = "other").encoded)
        }
        assertThrows(IllegalArgumentException::class.java) {
            VaultEnvelopeCodec.decode(encoded + byteArrayOf(0), identity)
        }
        assertThrows(IllegalArgumentException::class.java) {
            VaultEnvelopeCodec.decode(encoded.copyOfRange(0, encoded.size - 1), identity)
        }
        assertThrows(IllegalArgumentException::class.java) {
            VaultEnvelopeCodec.decode(malformedLengthRecord(), identity)
        }
    }

    @Test
    fun authenticatedUnwrapUsesCiphertextAndRejectsDifferentVaultIdentity() {
        val identity = sampleIdentity()
        val keyBytes = ByteArray(32) { (it * 7).toByte() }
        val key = SecretKeySpec(keyBytes, "AES")
        val nonce = ByteArray(12) { (it + 1).toByte() }
        val material = ByteArray(80) { (it * 11).toByte() }
        val encrypt =
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, nonce))
                updateAAD(identity.associatedData)
            }
        val sealed = encrypt.doFinal(material)
        val decrypt =
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
            }

        assertArrayEquals(material, VaultKeyEnvelopeCrypto.unwrap(identity, decrypt, sealed))

        val wrongIdentityDecrypt =
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, nonce))
            }
        assertThrows(javax.crypto.AEADBadTagException::class.java) {
            VaultKeyEnvelopeCrypto.unwrap(sampleIdentity(remoteVaultId = "other-vault"), wrongIdentityDecrypt, sealed)
        }
    }

    private fun malformedLengthRecord(): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.writeInt(0x5241564b)
                output.writeInt(1)
                output.writeInt(Int.MAX_VALUE)
            }
            bytes.toByteArray()
        }

    private fun sampleIdentity(
        accountId: String = "account-01",
        canonicalServer: String = "https://cloud.example.test/base",
        driveId: String = "drive-22",
        remoteVaultId: String = "resource-333",
    ) = VaultIdentity(accountId, canonicalServer, driveId, remoteVaultId)

    private fun writeEnvelopeFile(
        directory: File,
        identity: VaultIdentity,
        accountTagged: Boolean,
    ): String {
        val key = MessageDigest.getInstance("SHA-256").digest(identity.encoded).toHexForTest()
        val accountHash =
            MessageDigest
                .getInstance("SHA-256")
                .digest(identity.accountId.toByteArray(Charsets.UTF_8))
                .toHexForTest()
                .take(32)
        val prefix = if (accountTagged) "raiun_vault_v2_${accountHash}_${key}_" else "raiun_vault_v1_${key}_"
        val record = VaultEnvelope(identity.encoded, prefix + "0".repeat(32), ByteArray(12), ByteArray(96))
        File(directory, "$key.envelope").writeBytes(VaultEnvelopeCodec.encode(record))
        return key
    }

    private fun ByteArray.toHexForTest(): String = joinToString("") { "%02x".format(it) }
}
