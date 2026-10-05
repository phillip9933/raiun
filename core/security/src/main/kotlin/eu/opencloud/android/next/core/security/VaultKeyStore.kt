package eu.opencloud.android.next.core.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.AtomicFile
import androidx.biometric.BiometricManager
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import android.security.KeyStoreException as AndroidKeyStoreException

/**
 * Keeps an 80-byte verified rclone key bundle behind a per-vault auth-per-use Keystore key.
 * Callers must pass the returned Cipher as the BiometricPrompt CryptoObject; an authentication
 * callback by itself does not unlock anything.
 */
class VaultKeyStore(
    context: Context,
) {
    private val context = context.applicationContext
    private val directory = File(this.context.noBackupFilesDir, ENVELOPE_DIRECTORY)

    /** Start one-time enrollment. The returned Cipher must be authenticated before completion. */
    @Suppress("TooGenericExceptionCaught") // Delete a just-created Keystore alias before rethrowing any failure.
    fun prepareEnrollment(identity: VaultIdentity): Cipher =
        synchronized(LOCK) {
            requireStrongBiometrics()
            val identityKey = identityKey(identity)
            check(!hasEnvelopeFile(identity)) {
                "This vault already has biometric key protection. Forget it before enrolling again."
            }
            check(!pending.containsKey(identityKey)) { "Vault key enrollment is already in progress." }

            cleanOrphanAliases(identity)
            val alias = newAlias(identity)
            try {
                val key = generateVerifiedKey(alias)
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.ENCRYPT_MODE, key)
                val nonce = requireNotNull(cipher.iv) { "Keystore returned no nonce." }.copyOf()
                check(nonce.size == GCM_NONCE_BYTES) { "Keystore returned an invalid nonce." }
                pending[identityKey] = PendingEnrollment(identity, cipher, alias, nonce)
                cipher
            } catch (error: Throwable) {
                deleteAlias(alias)
                throw error
            }
        }

    /**
     * Commit a newly authenticated key bundle. An existing enrollment is never replaced; callers
     * must explicitly forget it first. The supplied buffer remains caller-owned.
     */
    @Suppress("TooGenericExceptionCaught", "InstanceOfCheckForException") // Clean up once, then preserve fatal errors.
    fun completeEnrollment(
        identity: VaultIdentity,
        cipher: Cipher,
        keyMaterial: ByteArray,
    ): Unit =
        synchronized(LOCK) {
            val identityKey = identityKey(identity)
            val operation = pending[identityKey]
            if (operation == null || operation.cipher !== cipher) {
                throw VaultEnrollmentException(VaultEnrollmentFailure.OPERATION_MISMATCH)
            }
            if (keyMaterial.size != KEY_MATERIAL_BYTES) {
                clearPending(identityKey, operation)
                throw VaultEnrollmentException(VaultEnrollmentFailure.INVALID_MATERIAL)
            }
            if (hasEnvelopeFile(identity)) {
                throw VaultEnrollmentException(VaultEnrollmentFailure.ALREADY_ENROLLED)
            }

            val record =
                try {
                    VaultKeyEnvelopeCrypto.seal(identity, operation.alias, operation.nonce, cipher, keyMaterial)
                } catch (error: Throwable) {
                    clearPending(identityKey, operation)
                    if (error is Error) throw error
                    throw classifyEnrollmentCryptoFailure(error)
                }
            try {
                writeEnvelope(identity, record)
                pending.remove(identityKey)
            } catch (error: Throwable) {
                // AtomicFile can report an error after the rename. Keep the key if a complete record
                // actually committed; otherwise remove the unusable in-flight alias.
                if (runCatching { readEnvelope(identity)?.alias == operation.alias }.getOrDefault(false)) {
                    pending.remove(identityKey)
                } else {
                    clearPending(identityKey, operation)
                }
                if (error is Error) throw error
                if (error is VaultEnrollmentException) throw error
                throw VaultEnrollmentException(VaultEnrollmentFailure.PERSISTENCE)
            } finally {
                record.identity.fill(0)
                record.ciphertext.fill(0)
                record.nonce.fill(0)
                operation.nonce.fill(0)
            }
        }

    /** Cancel a prompt/navigation attempt and remove only an uncommitted key for this identity. */
    fun cancelEnrollment(identity: VaultIdentity): Unit =
        synchronized(LOCK) {
            val identityKey = identityKey(identity)
            val operation = pending.remove(identityKey) ?: return@synchronized
            // If completion committed before cancellation acquired the lock, the operation is no
            // longer pending and its alias remains protected by the durable envelope.
            if (!hasEnvelopeFile(identity)) deleteAlias(operation.alias)
            operation.nonce.fill(0)
        }

    /** Prepare decryption. Use this Cipher as the BiometricPrompt CryptoObject. */
    fun prepareUnlock(identity: VaultIdentity): Cipher =
        synchronized(LOCK) {
            val identityKey = identityKey(identity)
            check(!pendingUnlocks.containsKey(identityKey)) { "Vault key unlock is already in progress." }
            val record = readEnvelope(identity) ?: throw VaultEnrollmentNotFoundException()
            val key =
                try {
                    loadKey(record.alias)
                } catch (error: GeneralSecurityException) {
                    throw VaultKeyUnavailableException(error)
                } ?: throw VaultEnrollmentNotFoundException()
            try {
                Cipher
                    .getInstance(TRANSFORMATION)
                    .apply {
                        init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, record.nonce))
                    }.also { pendingUnlocks[identityKey] = PendingUnlock(identity, it, record.ciphertext) }
            } catch (error: GeneralSecurityException) {
                record.ciphertext.fill(0)
                throw VaultKeyUnavailableException(error)
            }
        }

    /** Unwrap the vault bundle only by finalizing the authenticated Keystore Cipher. */
    fun completeUnlock(
        identity: VaultIdentity,
        cipher: Cipher,
    ): ByteArray =
        synchronized(LOCK) {
            val identityKey = identityKey(identity)
            val operation = pendingUnlocks[identityKey]
            check(operation != null && operation.cipher === cipher) {
                "No matching vault key unlock is in progress."
            }
            pendingUnlocks.remove(identityKey)
            try {
                VaultKeyEnvelopeCrypto.unwrap(identity, cipher, operation.ciphertext)
            } catch (error: GeneralSecurityException) {
                throw VaultKeyUnavailableException(error)
            } finally {
                operation.ciphertext.fill(0)
            }
        }

    /** Drop an unfinished prompt operation without changing its durable enrollment. */
    fun cancelUnlock(identity: VaultIdentity): Unit =
        synchronized(LOCK) {
            pendingUnlocks.remove(identityKey(identity))?.ciphertext?.fill(0)
        }

    /** Returns true when a structurally valid local envelope exists, including invalidated keys. */
    fun hasEnrollment(identity: VaultIdentity): Boolean =
        synchronized(LOCK) {
            readEnvelope(identity) != null
        }

    /** Validated identities with a durable envelope, including records lacking offer metadata. */
    fun enrolledIdentities(): List<VaultIdentity> =
        synchronized(LOCK) {
            VaultAccountEnvelopeInventory.identities(directory)
        }

    /** Forget local biometric convenience only. No account, vault, or server state is touched. */
    fun forget(identity: VaultIdentity): Unit =
        synchronized(LOCK) {
            val identityKey = identityKey(identity)
            pending.remove(identityKey)?.nonce?.fill(0)
            pendingUnlocks.remove(identityKey)?.ciphertext?.fill(0)
            atomicFile(identity).delete()
            cleanOrphanAliases(identity)
        }

    /**
     * Remove biometric convenience for an explicitly removed account. A full inventory is
     * validated before deletion; unattributable records fail closed instead of risking another
     * account's keys. The lock excludes in-flight enrollment and unlock completion.
     */
    fun forgetAccount(accountId: String): Unit =
        synchronized(LOCK) {
            require(accountId.isNotBlank())
            val keys = VaultAccountEnvelopeInventory.keysForAccount(directory, accountId).toMutableSet()
            pending.forEach { (key, operation) ->
                if (operation.identity.accountId == accountId) keys += key
            }
            pendingUnlocks.forEach { (key, operation) ->
                if (operation.identity.accountId == accountId) keys += key
            }

            pending.entries.removeAll { entry ->
                if (entry.value.identity.accountId == accountId) {
                    entry.value.nonce.fill(0)
                    true
                } else {
                    false
                }
            }
            pendingUnlocks.entries.removeAll { entry ->
                if (entry.value.identity.accountId == accountId) {
                    entry.value.ciphertext.fill(0)
                    true
                } else {
                    false
                }
            }

            // V2 aliases encode an account hash, so even keys orphaned by a process crash are
            // attributable. V1 orphan aliases cannot be assigned safely without an envelope.
            val prefixes = keys.flatMap { key -> listOf(legacyAliasPrefix(key), v2IdentityAliasPrefix(accountId, key)) }
            val accountPrefix = v2AccountAliasPrefix(accountId)
            val keyStore = loadKeyStore()
            val aliases = keyStore.aliases().toList()
            aliases
                .filter { alias -> alias.startsWith(accountPrefix) || prefixes.any(alias::startsWith) }
                .forEach(keyStore::deleteEntry)
            check(
                keyStore.aliases().toList().none { alias ->
                    alias.startsWith(accountPrefix) || prefixes.any(alias::startsWith)
                },
            ) { "Vault key cleanup failed." }
            // Delete envelopes last. If Keystore deletion fails, durable records preserve the
            // ownership mapping so a later removal attempt can retry safely.
            keys.forEach { key ->
                val base = envelopeFileForIdentityKey(key)
                listOf(base, File(base.path + ".bak"), File(base.path + ".new")).forEach { file ->
                    check(!file.exists() || file.delete()) { "Vault key cleanup failed." }
                }
            }
            check(
                keys.none { key ->
                    val base = envelopeFileForIdentityKey(key)
                    base.exists() || File(base.path + ".bak").exists() || File(base.path + ".new").exists()
                },
            ) { "Vault key cleanup failed." }
        }

    private fun requireStrongBiometrics() {
        if (BiometricManager.from(context).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            throw VaultBiometricProtectionUnavailableException()
        }
    }

    private fun generateVerifiedKey(alias: String): SecretKey {
        val strongBoxAvailable =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBoxAvailable) {
            val strongBoxKey =
                try {
                    generateKey(alias, strongBox = true)
                } catch (_: StrongBoxUnavailableException) {
                    null
                }
            if (strongBoxKey != null) {
                if (isAcceptableKey(strongBoxKey)) return strongBoxKey
                deleteAlias(alias)
            }
        }

        return generateHardwareFallback(alias)
    }

    // Providers may throw unchecked failures too; expose one fail-closed protection error.
    @Suppress("TooGenericExceptionCaught")
    private fun generateHardwareFallback(alias: String): SecretKey {
        val key =
            try {
                generateKey(alias, strongBox = false)
            } catch (error: Exception) {
                throw VaultBiometricProtectionUnavailableException(error)
            }
        if (!isAcceptableKey(key)) {
            deleteAlias(alias)
            throw VaultBiometricProtectionUnavailableException()
        }
        return key
    }

    private fun generateKey(
        alias: String,
        strongBox: Boolean,
    ): SecretKey {
        val builder =
            KeyGenParameterSpec
                .Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE_BITS)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && strongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
            init(builder.build())
            generateKey()
        }
    }

    private fun isAcceptableKey(key: SecretKey): Boolean =
        try {
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEY_STORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            val secureHardware =
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                        info.getSecurityLevel() == KeyProperties.SECURITY_LEVEL_STRONGBOX
                } else {
                    @Suppress("DEPRECATION")
                    info.isInsideSecureHardware()
                }
            info.isUserAuthenticationRequired() &&
                info.isUserAuthenticationRequirementEnforcedBySecureHardware() &&
                secureHardware
        } catch (_: Exception) {
            false
        }

    private fun readEnvelope(identity: VaultIdentity): VaultEnvelope? {
        val file = atomicFile(identity)
        if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return null
        val bytes = readEnvelopeBytes(file)
        return try {
            decodeEnvelope(identity, bytes)
        } finally {
            bytes.fill(0)
        }
    }

    private fun readEnvelopeBytes(file: AtomicFile): ByteArray =
        try {
            file.openRead().use { input ->
                if (input.available() !in 1..MAX_ENVELOPE_BYTES) throw VaultEnvelopeException()
                input.readBytes()
            }
        } catch (error: java.io.IOException) {
            throw VaultEnvelopeException(error)
        }

    private fun decodeEnvelope(
        identity: VaultIdentity,
        bytes: ByteArray,
    ): VaultEnvelope =
        try {
            VaultEnvelopeCodec.decode(bytes, identity.encoded).also { record ->
                require(
                    record.alias.startsWith(aliasPrefix(identity)) ||
                        record.alias.startsWith(legacyAliasPrefix(identityKey(identity))),
                )
            }
        } catch (error: java.io.IOException) {
            throw VaultEnvelopeException(error)
        } catch (error: IllegalArgumentException) {
            throw VaultEnvelopeException(error)
        }

    // Sanitize encode errors; preserve the original failure if rollback fails.
    @Suppress("TooGenericExceptionCaught", "SwallowedException")
    private fun writeEnvelope(
        identity: VaultIdentity,
        record: VaultEnvelope,
    ) {
        check(!hasEnvelopeFile(identity)) { "Refusing to replace a vault key envelope." }
        check(directory.exists() || directory.mkdirs()) { "Vault key storage is unavailable." }
        val encoded =
            try {
                VaultEnvelopeCodec.encode(record)
            } catch (error: IllegalArgumentException) {
                throw VaultEnrollmentException(VaultEnrollmentFailure.ENVELOPE_ENCODING)
            }
        val atomicFile = atomicFile(identity)
        var stream: FileOutputStream? = null
        try {
            stream = atomicFile.startWrite()
            stream.write(encoded)
            atomicFile.finishWrite(stream)
            stream = null
        } catch (error: Throwable) {
            // Preserve the original write failure even if rollback cannot complete.
            stream?.let { runCatching { atomicFile.failWrite(it) } }
            throw error
        } finally {
            encoded.fill(0)
        }
    }

    private fun hasEnvelopeFile(identity: VaultIdentity): Boolean {
        val file = atomicFile(identity).baseFile
        return file.exists() || File(file.path + ".bak").exists()
    }

    private fun atomicFile(identity: VaultIdentity): AtomicFile =
        AtomicFile(File(directory, "${identityKey(identity)}.envelope"))

    private fun identityKey(identity: VaultIdentity): String =
        MessageDigest.getInstance("SHA-256").digest(identity.encoded).toHex()

    private fun aliasPrefix(identity: VaultIdentity): String =
        v2IdentityAliasPrefix(identity.accountId, identityKey(identity))

    private fun v2AccountAliasPrefix(accountId: String): String =
        "${ALIAS_PREFIX_V2}${MessageDigest.getInstance(
            "SHA-256",
        ).digest(accountId.toByteArray(StandardCharsets.UTF_8)).toHex().take(32)}_"

    private fun v2IdentityAliasPrefix(
        accountId: String,
        key: String,
    ): String = "${v2AccountAliasPrefix(accountId)}${key}_"

    private fun legacyAliasPrefix(key: String): String = "${ALIAS_PREFIX}${key}_"

    private fun newAlias(identity: VaultIdentity): String =
        aliasPrefix(identity) + ByteArray(16).also(random::nextBytes).toHex()

    private fun cleanOrphanAliases(identity: VaultIdentity) {
        val prefixes = listOf(aliasPrefix(identity), legacyAliasPrefix(identityKey(identity)))
        val record = runCatching { readEnvelope(identity) }.getOrNull()
        val keep = record?.alias
        val keyStore = loadKeyStore()
        val aliases = keyStore.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            if (prefixes.any(alias::startsWith) && alias != keep) keyStore.deleteEntry(alias)
        }
    }

    private fun loadKey(alias: String): SecretKey? {
        if (!alias.startsWith(ALIAS_PREFIX) && !alias.startsWith(ALIAS_PREFIX_V2)) throw VaultEnvelopeException()
        val keyStore = loadKeyStore()
        return (keyStore.getKey(alias, null) as? SecretKey)
    }

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private fun deleteAlias(alias: String) {
        runCatching { loadKeyStore().deleteEntry(alias) }
    }

    private fun clearPending(
        identityKey: String,
        operation: PendingEnrollment,
    ) {
        pending.remove(identityKey)
        operation.nonce.fill(0)
        if (!runCatching {
                val file = envelopeFileForIdentityKey(identityKey)
                file.exists() || File(file.path + ".bak").exists()
            }.getOrDefault(true)
        ) {
            deleteAlias(operation.alias)
        }
    }

    private fun envelopeFileForIdentityKey(identityKey: String): File = File(directory, "$identityKey.envelope")

    private data class PendingEnrollment(
        val identity: VaultIdentity,
        val cipher: Cipher,
        val alias: String,
        val nonce: ByteArray,
    )

    private data class PendingUnlock(
        val identity: VaultIdentity,
        val cipher: Cipher,
        val ciphertext: ByteArray,
    )

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val ENVELOPE_DIRECTORY = "vault-key-envelopes"
        private const val ALIAS_PREFIX = "raiun_vault_v1_"
        private const val ALIAS_PREFIX_V2 = "raiun_vault_v2_"
        private const val KEY_SIZE_BITS = 256
        private const val KEY_MATERIAL_BYTES = 80
        private const val GCM_NONCE_BYTES = 12
        private const val GCM_TAG_BITS = 128
        private const val MAX_ENVELOPE_BYTES = 20 * 1024
        private val LOCK = Any()
        private val pending = mutableMapOf<String, PendingEnrollment>()
        private val pendingUnlocks = mutableMapOf<String, PendingUnlock>()
        private val random = SecureRandom()
    }
}

internal data class VaultEnvelope(
    val identity: ByteArray,
    val alias: String,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
)

internal object VaultEnvelopeCodec {
    private const val MAGIC = 0x5241564b // RAVK
    private const val VERSION = 1
    private const val MAX_IDENTITY_BYTES = 17 * 1024
    private const val MAX_ALIAS_BYTES = 160
    private const val NONCE_BYTES = 12
    private const val SEALED_KEY_BYTES = 96
    private const val MAX_ENVELOPE_BYTES = 20 * 1024

    fun encode(envelope: VaultEnvelope): ByteArray {
        require(envelope.identity.size in 1..MAX_IDENTITY_BYTES)
        require(envelope.alias.toByteArray(Charsets.UTF_8).size in 1..MAX_ALIAS_BYTES)
        require(envelope.nonce.size == NONCE_BYTES)
        require(envelope.ciphertext.size == SEALED_KEY_BYTES)
        val output = ByteArrayOutputStream()
        DataOutputStream(output).use { data ->
            data.writeInt(MAGIC)
            data.writeInt(VERSION)
            data.writeBoundedBytes(envelope.identity, MAX_IDENTITY_BYTES)
            data.writeBoundedBytes(envelope.alias.toByteArray(Charsets.UTF_8), MAX_ALIAS_BYTES)
            data.writeBoundedBytes(envelope.nonce, NONCE_BYTES)
            data.writeBoundedBytes(envelope.ciphertext, SEALED_KEY_BYTES)
        }
        return output.toByteArray().also { require(it.size <= MAX_ENVELOPE_BYTES) }
    }

    fun decode(
        bytes: ByteArray,
        expectedIdentity: ByteArray,
    ): VaultEnvelope =
        decodeUnbound(bytes).also { envelope ->
            require(MessageDigest.isEqual(envelope.identity, expectedIdentity))
        }

    fun decodeUnbound(bytes: ByteArray): VaultEnvelope {
        require(bytes.size in 12..MAX_ENVELOPE_BYTES)
        DataInputStream(ByteArrayInputStream(bytes)).use { data ->
            require(data.readInt() == MAGIC)
            require(data.readInt() == VERSION)
            val identity = data.readBoundedBytes(MAX_IDENTITY_BYTES)
            val aliasBytes = data.readBoundedBytes(MAX_ALIAS_BYTES)
            val alias = aliasBytes.toString(Charsets.UTF_8)
            require(alias.isNotBlank() && alias.none { it.isISOControl() })
            val nonce = data.readBoundedBytes(NONCE_BYTES).also { require(it.size == NONCE_BYTES) }
            val ciphertext =
                data.readBoundedBytes(SEALED_KEY_BYTES).also {
                    require(it.size == SEALED_KEY_BYTES)
                }
            require(data.available() == 0)
            return VaultEnvelope(identity, alias, nonce, ciphertext)
        }
    }

    private fun DataOutputStream.writeBoundedBytes(
        bytes: ByteArray,
        maximum: Int,
    ) {
        require(bytes.size in 1..maximum)
        writeInt(bytes.size)
        write(bytes)
    }

    private fun DataInputStream.readBoundedBytes(maximum: Int): ByteArray {
        val length = readInt()
        require(length in 1..maximum && length <= available())
        return ByteArray(length).also(::readFully)
    }
}

/** Filesystem-only inventory, kept separate so account selection can be tested on the JVM. */
internal object VaultAccountEnvelopeInventory {
    private const val MAX_ENVELOPE_BYTES = 20 * 1024
    private const val MAX_FIELD_BYTES = 4096
    private const val LEGACY_PREFIX = "raiun_vault_v1_"
    private const val ACCOUNT_PREFIX = "raiun_vault_v2_"
    private val fileName = Regex("^([0-9a-f]{64})\\.envelope(?:\\.bak|\\.new)?$")

    fun keysForAccount(
        directory: File,
        accountId: String,
    ): Set<String> {
        if (!directory.exists()) return emptySet()
        check(directory.isDirectory) { "Vault key storage is unavailable." }
        val files = checkNotNull(directory.listFiles()) { "Vault key storage is unavailable." }
        return files
            .mapNotNull { file ->
                val fileKey = validatedFileKey(file)
                val bytes = file.readBytes()
                try {
                    val record = VaultEnvelopeCodec.decodeUnbound(bytes)
                    try {
                        val identity = decodeIdentity(record.identity)
                        val key = MessageDigest.getInstance("SHA-256").digest(record.identity).toHex()
                        require(fileKey == key)
                        val accountHash =
                            MessageDigest
                                .getInstance("SHA-256")
                                .digest(identity.accountId.toByteArray(StandardCharsets.UTF_8))
                                .toHex()
                                .take(32)
                        require(
                            record.alias.startsWith("${LEGACY_PREFIX}${key}_") ||
                                record.alias.startsWith("${ACCOUNT_PREFIX}${accountHash}_${key}_"),
                        )
                        key.takeIf { identity.accountId == accountId }
                    } finally {
                        record.identity.fill(0)
                        record.nonce.fill(0)
                        record.ciphertext.fill(0)
                    }
                } catch (error: java.io.IOException) {
                    throw VaultEnvelopeException(error)
                } catch (error: IllegalArgumentException) {
                    throw VaultEnvelopeException(error)
                } finally {
                    bytes.fill(0)
                }
            }.toSet()
    }

    fun identities(directory: File): List<VaultIdentity> {
        if (!directory.exists()) return emptyList()
        check(directory.isDirectory) { "Vault key storage is unavailable." }
        val files = checkNotNull(directory.listFiles()) { "Vault key storage is unavailable." }
        return files
            .mapNotNull { file ->
                val fileKey = validatedFileKey(file)
                val bytes = file.readBytes()
                try {
                    val record = VaultEnvelopeCodec.decodeUnbound(bytes)
                    try {
                        val identity = decodeIdentity(record.identity)
                        val key = MessageDigest.getInstance("SHA-256").digest(record.identity).toHex()
                        require(fileKey == key)
                        val accountHash =
                            MessageDigest
                                .getInstance("SHA-256")
                                .digest(identity.accountId.toByteArray(StandardCharsets.UTF_8))
                                .toHex()
                                .take(32)
                        require(
                            record.alias.startsWith("${LEGACY_PREFIX}${key}_") ||
                                record.alias.startsWith("${ACCOUNT_PREFIX}${accountHash}_${key}_"),
                        )
                        identity
                    } finally {
                        record.identity.fill(0)
                        record.nonce.fill(0)
                        record.ciphertext.fill(0)
                    }
                } catch (error: java.io.IOException) {
                    throw VaultEnvelopeException(error)
                } catch (error: IllegalArgumentException) {
                    throw VaultEnvelopeException(error)
                } finally {
                    bytes.fill(0)
                }
            }.distinct()
    }

    private fun validatedFileKey(file: File): String {
        val match = fileName.matchEntire(file.name) ?: throw VaultEnvelopeException()
        if (!file.isFile || file.length() !in 1..MAX_ENVELOPE_BYTES.toLong()) {
            throw VaultEnvelopeException()
        }
        return match.groupValues[1]
    }

    private fun decodeIdentity(bytes: ByteArray): VaultIdentity {
        val fields =
            DataInputStream(ByteArrayInputStream(bytes)).use { data ->
                require(data.readInt() == 1)
                List(4) {
                    val length = data.readInt()
                    require(length in 1..MAX_FIELD_BYTES && length <= data.available())
                    val value = ByteArray(length).also(data::readFully)
                    StandardCharsets.UTF_8
                        .newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT)
                        .decode(ByteBuffer.wrap(value))
                        .toString()
                }.also { require(data.available() == 0) }
            }
        return VaultIdentity(fields[0], fields[1], fields[2], fields[3]).also {
            require(MessageDigest.isEqual(it.encoded, bytes))
        }
    }
}

/** Small JVM-testable seam for the actual authenticated unwrap operation. */
internal object VaultKeyEnvelopeCrypto {
    private const val KEY_MATERIAL_BYTES = 80

    @Suppress("TooGenericExceptionCaught") // Wipe the nonce for every failed provider operation, then rethrow.
    fun seal(
        identity: VaultIdentity,
        alias: String,
        nonce: ByteArray,
        cipher: Cipher,
        keyMaterial: ByteArray,
    ): VaultEnvelope {
        require(nonce.size == 12)
        val storedNonce = nonce.copyOf()
        return try {
            // The CryptoObject has now been authorized by BiometricPrompt. Android Keystore can
            // cache an authentication error from updateAAD before that callback and report it
            // only at doFinal, even when the fingerprint succeeds.
            cipher.updateAAD(identity.associatedData)
            VaultEnvelope(identity.encoded, alias, storedNonce, cipher.doFinal(keyMaterial))
        } catch (error: Throwable) {
            storedNonce.fill(0)
            throw error
        }
    }

    fun unwrap(
        identity: VaultIdentity,
        cipher: Cipher,
        ciphertext: ByteArray,
    ): ByteArray {
        cipher.updateAAD(identity.associatedData)
        val plaintext = cipher.doFinal(ciphertext)
        if (plaintext.size != KEY_MATERIAL_BYTES) {
            plaintext.fill(0)
            throw VaultEnvelopeException()
        }
        return plaintext
    }
}

class VaultBiometricProtectionUnavailableException(
    cause: Throwable? = null,
) : IllegalStateException("Hardware-enforced strong biometric key protection is unavailable.", cause)

/** Safe, stable failure stage for diagnosing an enrollment without exposing provider text or key data. */
enum class VaultEnrollmentFailure {
    INVALID_MATERIAL,
    OPERATION_MISMATCH,
    ALREADY_ENROLLED,
    AUTHORIZATION,
    KEY_INVALIDATED,
    CRYPTO_FINALIZATION,
    ENVELOPE_ENCODING,
    PERSISTENCE,
}

class VaultEnrollmentException(
    val failure: VaultEnrollmentFailure,
    val cryptoCause: VaultEnrollmentCryptoCause? = null,
    val keyStoreErrorCode: Int? = null,
) : IllegalStateException("Biometric vault enrollment failed: ${failure.name}.")

enum class VaultEnrollmentCryptoCause {
    ILLEGAL_BLOCK_SIZE,
    BAD_PADDING,
    OTHER,
}

internal fun classifyEnrollmentCryptoFailure(error: Throwable): VaultEnrollmentException {
    val causes = generateSequence(error) { it.cause }.take(8).toList()
    val failure =
        when {
            causes.any { it is KeyPermanentlyInvalidatedException } -> VaultEnrollmentFailure.KEY_INVALIDATED
            causes.any { it is UserNotAuthenticatedException } -> VaultEnrollmentFailure.AUTHORIZATION
            else -> VaultEnrollmentFailure.CRYPTO_FINALIZATION
        }
    val cryptoCause =
        when {
            causes.any { it is IllegalBlockSizeException } -> VaultEnrollmentCryptoCause.ILLEGAL_BLOCK_SIZE
            causes.any { it is BadPaddingException } -> VaultEnrollmentCryptoCause.BAD_PADDING
            else -> VaultEnrollmentCryptoCause.OTHER
        }
    val keyStoreErrorCode =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            causes
                .filterIsInstance<AndroidKeyStoreException>()
                .firstOrNull()
                ?.let { runCatching { it.numericErrorCode }.getOrNull() }
                ?.takeIf { it in 0..255 }
        } else {
            null
        }
    return VaultEnrollmentException(failure, cryptoCause, keyStoreErrorCode)
}

class VaultEnrollmentNotFoundException :
    IllegalStateException("No biometric key enrollment is available for this vault.")

class VaultKeyUnavailableException(
    cause: Throwable? = null,
) : IllegalStateException("The biometric vault key could not be used. Unlock with the vault password.", cause)

class VaultEnvelopeException(
    cause: Throwable? = null,
) : IllegalStateException("The local biometric vault enrollment is invalid. Unlock with the vault password.", cause)

private fun ByteArray.toHex(): String = joinToString(separator = "") { byte -> "%02x".format(byte) }
