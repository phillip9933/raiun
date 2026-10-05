package eu.opencloud.android.next.core.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator

/** Exercises account cleanup only; these synthetic keys do not test biometric authentication. */
@RunWith(AndroidJUnit4::class)
class VaultKeyStoreAccountCleanupTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val aliasesCreated = mutableSetOf<String>()
    private val envelopesCreated = mutableSetOf<File>()

    @Test
    fun forgetAccountDeletesItsEnvelopesAndKeysButPreservesAnotherAccount() {
        val account = "cleanup-${UUID.randomUUID()}"
        val otherAccount = "cleanup-other-${UUID.randomUUID()}"
        val accountIdentities =
            listOf(
                identity(account, "drive-a", "vault-a"),
                identity(account, "drive-b", "vault-b"),
            )
        val otherIdentity = identity(otherAccount, "drive-c", "vault-c")

        try {
            val accountFixtures = accountIdentities.map(::createEnvelope)
            val otherFixture = createEnvelope(otherIdentity)
            val orphanAlias =
                v2AccountPrefix(account) + "orphan_" + UUID.randomUUID().toString().replace("-", "")
            createKey(orphanAlias)
            val before = androidKeyStore()

            accountFixtures.forEach { fixture -> assertTrue(fixture.file.exists()) }
            assertTrue(otherFixture.file.exists())
            aliasesCreated.forEach { alias -> assertTrue(before.containsAlias(alias)) }

            // This asserts account cleanup only; no biometric prompt or authentication requirement is tested.
            VaultKeyStore(context).forgetAccount(account)

            val after = androidKeyStore()
            accountFixtures.forEach { fixture ->
                assertFalse(fixture.file.exists())
                assertFalse(after.containsAlias(fixture.alias))
            }
            assertFalse(after.containsAlias(orphanAlias))
            assertTrue(otherFixture.file.exists())
            assertTrue(after.containsAlias(otherFixture.alias))
        } finally {
            cleanupFixtures()
        }
    }

    @Test
    fun corruptInventoryFailsClosedBeforeDeletingAnySyntheticKey() {
        val account = "cleanup-corrupt-${UUID.randomUUID()}"
        val targetIdentity = identity(account, "drive-a", "vault-a")
        val otherIdentity = identity("cleanup-preserved-${UUID.randomUUID()}", "drive-b", "vault-b")

        try {
            val targetFixture = createEnvelope(targetIdentity)
            val otherFixture = createEnvelope(otherIdentity)
            val corruptFile =
                File(envelopeDirectory(), "corrupt-${UUID.randomUUID()}.envelope").apply {
                    writeBytes("not a valid vault envelope".toByteArray(StandardCharsets.UTF_8))
                }
            envelopesCreated += corruptFile
            assertThrows(VaultEnvelopeException::class.java) {
                VaultKeyStore(context).forgetAccount(account)
            }

            val after = androidKeyStore()
            assertTrue(targetFixture.file.exists())
            assertTrue(otherFixture.file.exists())
            assertTrue(corruptFile.exists())
            aliasesCreated.forEach { alias -> assertTrue(after.containsAlias(alias)) }
        } finally {
            cleanupFixtures()
        }
    }

    private fun createEnvelope(identity: VaultIdentity): SyntheticEnvelope {
        val alias = newAlias(identity)
        val key = createKey(alias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(identity.associatedData)
        val nonce = requireNotNull(cipher.iv).copyOf()
        val ciphertext = cipher.doFinal(ByteArray(KEY_MATERIAL_BYTES))
        val record =
            VaultEnvelope(
                identity = identity.encoded,
                alias = alias,
                nonce = nonce,
                ciphertext = ciphertext,
            )
        val file = File(envelopeDirectory(), "${identityHash(identity)}.envelope")
        file.writeBytes(VaultEnvelopeCodec.encode(record))
        envelopesCreated += file
        ciphertext.fill(0)
        nonce.fill(0)
        return SyntheticEnvelope(alias, file)
    }

    private fun createKey(alias: String): javax.crypto.SecretKey {
        aliasesCreated += alias
        return KeyGenerator
            .getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            .apply {
                init(
                    KeyGenParameterSpec
                        .Builder(
                            alias,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setKeySize(KEY_SIZE_BITS)
                        .build(),
                )
            }.generateKey()
    }

    private fun identity(
        account: String,
        drive: String,
        vault: String,
    ) = VaultIdentity(account, "https://cleanup.invalid", drive, vault)

    private fun newAlias(identity: VaultIdentity): String =
        "${identityPrefix(identity)}${UUID.randomUUID().toString().replace("-", "")}".also(aliasesCreated::add)

    private fun identityPrefix(identity: VaultIdentity): String =
        "${v2AccountPrefix(identity.accountId)}${identityHash(identity)}_"

    private fun v2AccountPrefix(accountId: String): String =
        "${V2_ALIAS_PREFIX}${sha256(accountId.toByteArray(StandardCharsets.UTF_8)).toHex().take(32)}_"

    private fun identityHash(identity: VaultIdentity): String = sha256(identity.encoded).toHex()

    private fun envelopeDirectory(): File = File(context.noBackupFilesDir, ENVELOPE_DIRECTORY).apply { mkdirs() }

    private fun androidKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private fun cleanupFixtures() {
        val keyStore = androidKeyStore()
        aliasesCreated.forEach { alias -> if (keyStore.containsAlias(alias)) keyStore.deleteEntry(alias) }
        envelopesCreated.forEach(File::delete)
        aliasesCreated.clear()
        envelopesCreated.clear()
    }

    private data class SyntheticEnvelope(
        val alias: String,
        val file: File,
    )

    private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte -> "%02x".format(byte) }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val ENVELOPE_DIRECTORY = "vault-key-envelopes"
        const val V2_ALIAS_PREFIX = "raiun_vault_v2_"
        const val KEY_SIZE_BITS = 256
        const val KEY_MATERIAL_BYTES = 80
    }
}
