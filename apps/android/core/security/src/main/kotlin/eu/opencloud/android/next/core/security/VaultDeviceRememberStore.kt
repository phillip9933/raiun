package eu.opencloud.android.next.core.security

import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.ProviderException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/** Stable account ownership snapshot supplied by the repository, never a token or hashCode. */
data class VaultRememberBinding(
    val incarnation: String,
    val accountDigest: String,
) {
    init {
        require(incarnation.matches(Regex("[0-9a-f]{32}")))
        require(accountDigest.matches(Regex("[0-9a-f]{64}")))
    }
}

enum class VaultRememberChoice { REMEMBERED, DECLINED }

/** Opaque admission snapshot. It contains no secret and is only useful to its originating store. */
class VaultDeviceRememberGrant internal constructor(
    internal val storeId: String,
    internal val identityHash: String,
    internal val binding: VaultRememberBinding,
    internal val globalEpoch: Long,
    internal val accountEpoch: Long,
    internal val identityEpoch: Long,
)

internal enum class VaultDeviceRememberFailpoint {
    AFTER_REMEMBERED_CHOICE_COMMIT,
    BEFORE_POST_COMMIT_REVOCATION_WRITE,
    AFTER_POST_COMMIT_REVOCATION_WRITE,
    AFTER_DECRYPTION,
}

internal data class VaultDeviceRememberTestHooks(
    val aliasFactory: ((VaultIdentity) -> String)? = null,
    val failpoint: ((VaultDeviceRememberFailpoint, ByteArray?) -> Unit)? = null,
)

private data class RememberAad(
    val identity: VaultIdentity,
    val binding: VaultRememberBinding,
    val globalEpoch: Long,
    val accountEpoch: Long,
    val identityEpoch: Long,
    val alias: String,
    val nonce: ByteArray,
)

/** Durable, device-unlock-gated vault-key convenience, isolated from biometric enrollment. */
class VaultDeviceRememberStore internal constructor(
    private val directory: File,
    private val crypto: VaultDeviceRememberCrypto,
    private val askEveryTime: () -> Boolean,
    private val secureLockConfigured: () -> Boolean,
    private val deviceAllowed: () -> Boolean,
    private val testHooks: VaultDeviceRememberTestHooks = VaultDeviceRememberTestHooks(),
) {
    private val disk = VaultDeviceRememberDisk(directory)
    private val aliasFactory: (VaultIdentity) -> String =
        testHooks.aliasFactory ?: { identity ->
            "$ALIAS_PREFIX${identity.hashForRemember()}_${randomHex(16)}"
        }
    private val failpoint: (VaultDeviceRememberFailpoint, ByteArray?) -> Unit = testHooks.failpoint ?: { _, _ -> }

    constructor(context: Context) : this(
        File(context.applicationContext.noBackupFilesDir.canonicalFile, DIRECTORY),
        AndroidVaultDeviceRememberCrypto(),
        { VaultUnlockPolicy(context.applicationContext).askEveryTime() },
        { context.applicationContext.getSystemService(KeyguardManager::class.java)?.isDeviceSecure == true },
        {
            val app = AppLock(context.applicationContext)
            val keyguard = context.applicationContext.getSystemService(KeyguardManager::class.java)
            keyguard?.isDeviceSecure == true &&
                keyguard?.isDeviceLocked == false &&
                app.canOpenApp() &&
                context.applicationContext.getSystemService(PowerManager::class.java)?.isInteractive == true
        },
        VaultDeviceRememberTestHooks(),
    )

    fun isSupported(): Boolean = crypto.isPlatformSupported() && runCatching(secureLockConfigured).getOrDefault(false)

    /** Commit the mode and durable strict-mode revocation under the same cross-instance fence. */
    internal fun changeAskEveryTime(
        value: Boolean,
        commit: () -> Unit,
    ) = guarded {
        withLedgerLock {
            if (value) {
                val state = readLedger()
                writeLedger(
                    state.copy(
                        globalEpoch = state.globalEpoch + 1L,
                        choices = state.choices.filterValues { it.choice == VaultRememberChoice.DECLINED },
                    ),
                )
            }
            commit()
            if (value) cleanupOwnedRecordsLocked()
        }
    }

    /** Capture durable revocation generations before the caller starts asynchronous work. */
    fun begin(
        identity: VaultIdentity,
        binding: VaultRememberBinding,
    ): VaultDeviceRememberGrant? =
        guarded {
            withLedgerLock {
                if (askEveryTime() || !isSupported() || !deviceAllowedNow()) return@withLedgerLock null
                val state = readLedger()
                VaultDeviceRememberGrant(
                    storeId(),
                    identityHash(identity),
                    binding,
                    state.globalEpoch,
                    state.accountEpochs[identity.accountId] ?: 0L,
                    state.identityEpochs[identityHash(identity)] ?: 0L,
                )
            }
        }

    /** Stores only freshly accepted, verified 80-byte vault material. Caller retains its array. */
    fun remember(
        grant: VaultDeviceRememberGrant?,
        identity: VaultIdentity,
        binding: VaultRememberBinding,
        verifiedKeyMaterial: ByteArray,
        permit: () -> Boolean,
    ): Boolean =
        guarded {
            if (!rememberRequestAllowed(grant, identity, binding, verifiedKeyMaterial, permit)) {
                return@guarded false
            }
            val acceptedGrant = requireNotNull(grant)
            withLedgerLock { Enrollment(acceptedGrant, identity, binding, verifiedKeyMaterial, permit).run() }
        }

    private fun rememberRequestAllowed(
        grant: VaultDeviceRememberGrant?,
        identity: VaultIdentity,
        binding: VaultRememberBinding,
        material: ByteArray,
        permit: () -> Boolean,
    ): Boolean =
        grant != null &&
            grant.storeId == storeId() &&
            material.size == KEY_MATERIAL_BYTES &&
            grant.identityHash == identityHash(identity) &&
            grant.binding == binding &&
            stillAllowed(permit)

    private inner class Enrollment(
        private val grant: VaultDeviceRememberGrant,
        private val identity: VaultIdentity,
        private val binding: VaultRememberBinding,
        private val material: ByteArray,
        private val permit: () -> Boolean,
    ) {
        private val keyHash = identityHash(identity)
        private var alias: String? = null
        private var nonce: ByteArray? = null
        private var ciphertext: ByteArray? = null
        private var keyCreated = false
        private var recordWritten = false
        private var choiceCommitAttempted = false

        fun run(): Boolean =
            try {
                enroll()
            } catch (error: VaultDeviceRememberOutcomeUnknownException) {
                throw error
            } catch (_: GeneralSecurityException) {
                recoverFailure()
            } catch (_: IOException) {
                recoverFailure()
            } catch (_: IllegalStateException) {
                recoverFailure()
            } catch (_: IllegalArgumentException) {
                recoverFailure()
            } catch (_: SecurityException) {
                recoverFailure()
            } catch (_: ProviderException) {
                recoverFailure()
            } finally {
                ciphertext?.fill(0)
                nonce?.fill(0)
            }

        private fun enroll(): Boolean {
            val before = readLedger()
            return when {
                !grantCurrent(grant, identity, before) || !stillAllowed(permit) -> false
                before.choices[keyHash]?.choice == VaultRememberChoice.REMEMBERED -> false
                else -> {
                    discardOrphan()
                    completeEnrollment(before)
                }
            }
        }

        private fun completeEnrollment(before: RememberLedger): Boolean =
            if (!createEncryptedEnvelope(before)) {
                abortUncommitted()
            } else if (!commitRememberedChoice(before)) {
                abortUncommitted()
            } else {
                failpoint(VaultDeviceRememberFailpoint.AFTER_REMEMBERED_CHOICE_COMMIT, null)
                if (stillAllowed(permit)) true else rejectAfterCommit()
            }

        private fun discardOrphan() {
            val orphanAlias = readRecordAlias(identity) ?: return
            // An envelope without consent is a crash orphan, never an enrollment to adopt.
            deleteRecord(identity)
            deleteAliases(identity, orphanAlias)
        }

        private fun createEncryptedEnvelope(before: RememberLedger): Boolean {
            alias = aliasFactory(identity)
            val ownedAlias = requireNotNull(alias)
            check(ownedAlias.matches(Regex("${Regex.escape(aliasPrefix(identity))}[0-9a-f]{16}")))
            val key = crypto.create(ownedAlias)
            keyCreated = true
            if (!crypto.isAcceptable(key) || !stillAllowed(permit)) return false

            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key)
            nonce = requireNotNull(cipher.iv).copyOf()
            val ownedNonce = requireNotNull(nonce)
            if (ownedNonce.size != NONCE_BYTES) throw VaultDeviceRememberUnavailableException()
            updateAad(cipher, aadFor(before, ownedAlias, ownedNonce))
            ciphertext = cipher.doFinal(material)
            return stillAllowed(permit) && grantCurrent(grant, identity, readLedger())
        }

        private fun commitRememberedChoice(before: RememberLedger): Boolean {
            val cipherBytes = requireNotNull(ciphertext)
            val nonceBytes = requireNotNull(nonce)
            val selectedAlias = requireNotNull(alias)
            writeRecord(
                identity,
                RememberRecord(
                    identity,
                    binding,
                    before.globalEpoch,
                    before.accountEpochs[identity.accountId] ?: 0L,
                    before.identityEpochs[keyHash] ?: 0L,
                    selectedAlias,
                    nonceBytes,
                    cipherBytes,
                ),
            )
            recordWritten = true
            val current = readLedger()
            if (!stillAllowed(permit) || !grantCurrent(grant, identity, current)) return false
            choiceCommitAttempted = true
            writeLedger(
                current.copy(
                    choices =
                        current.choices +
                            (keyHash to ChoiceRecord(identity, binding, VaultRememberChoice.REMEMBERED)),
                ),
            )
            return true
        }

        private fun rejectAfterCommit(): Boolean {
            if (!revokeCommittedChoice()) return unknownAfterCleanup()
            return abortUncommitted()
        }

        private fun revokeCommittedChoice(): Boolean =
            try {
                failpoint(VaultDeviceRememberFailpoint.BEFORE_POST_COMMIT_REVOCATION_WRITE, null)
                rotateCommittedChoiceEpoch()
                failpoint(VaultDeviceRememberFailpoint.AFTER_POST_COMMIT_REVOCATION_WRITE, null)
                true
            } catch (_: GeneralSecurityException) {
                false
            } catch (_: IOException) {
                false
            } catch (_: IllegalStateException) {
                false
            } catch (_: IllegalArgumentException) {
                false
            } catch (_: SecurityException) {
                false
            } catch (_: ProviderException) {
                false
            }

        private fun rotateCommittedChoiceEpoch() {
            val committed = readLedger()
            writeLedger(
                committed.copy(
                    identityEpochs =
                        committed.identityEpochs +
                            (keyHash to ((committed.identityEpochs[keyHash] ?: 0L) + 1L)),
                    choices = committed.choices - keyHash,
                ),
            )
        }

        private fun recoverFailure(): Boolean {
            if (choiceCommitAttempted) {
                runCatching { rotateCommittedChoiceEpoch() }
                return unknownAfterCleanup()
            }
            return abortUncommitted()
        }

        private fun unknownAfterCleanup(): Nothing {
            cleanupNewEnrollment(identity, requireNotNull(alias), keyCreated, recordWritten)
            throw VaultDeviceRememberOutcomeUnknownException()
        }

        private fun abortUncommitted(): Boolean {
            if (!keyCreated && !recordWritten) return false
            if (!cleanupNewEnrollment(identity, requireNotNull(alias), keyCreated, recordWritten)) {
                throw VaultDeviceRememberOutcomeUnknownException()
            }
            keyCreated = false
            recordWritten = false
            return false
        }

        private fun aadFor(
            before: RememberLedger,
            selectedAlias: String,
            selectedNonce: ByteArray,
        ) = RememberAad(
            identity,
            binding,
            before.globalEpoch,
            before.accountEpochs[identity.accountId] ?: 0L,
            before.identityEpochs[keyHash] ?: 0L,
            selectedAlias,
            selectedNonce,
        )
    }

    /** Decrypts only for the exact owner incarnation and current unlocked-device state. */
    fun restore(
        identity: VaultIdentity,
        binding: VaultRememberBinding,
        permit: () -> Boolean,
    ): VaultUnlockKey? = RestoreOperation(identity, binding, permit).run()

    private inner class RestoreOperation(
        private val identity: VaultIdentity,
        private val binding: VaultRememberBinding,
        private val permit: () -> Boolean,
    ) {
        private var ownedMaterial: ByteArray? = null
        private var candidate: VaultUnlockKey? = null

        fun run(): VaultUnlockKey? {
            var transferred = false
            var result: VaultUnlockKey? = null
            try {
                result = guarded { withLedgerLock { restoreLocked() } }
                if (result != null && result.isCurrent()) {
                    transferred = true
                    ownedMaterial = null
                    candidate = null
                } else {
                    result?.close()
                    result = null
                }
            } catch (_: GeneralSecurityException) {
                result = null
            } catch (_: IOException) {
                result = null
            } catch (_: IllegalStateException) {
                result = null
            } catch (_: IllegalArgumentException) {
                result = null
            } catch (_: SecurityException) {
                result = null
            } catch (_: ProviderException) {
                result = null
            } finally {
                if (!transferred) {
                    candidate?.close()
                    ownedMaterial?.fill(0)
                }
            }
            return result
        }

        private fun restoreLocked(): VaultUnlockKey? = if (!accessAllowed()) null else restoreWithState(readLedger())

        private fun restoreWithState(state: RememberLedger): VaultUnlockKey? {
            val keyHash = identityHash(identity)
            if (!hasCurrentConsent(state, keyHash)) return null
            return restoreRecord(state, keyHash)
        }

        private fun restoreRecord(
            state: RememberLedger,
            keyHash: String,
        ): VaultUnlockKey? {
            val record = readRecord(identity) ?: return null
            return try {
                decryptCurrentRecord(record, state, keyHash)
            } finally {
                record.clear()
            }
        }

        private fun hasCurrentConsent(
            state: RememberLedger,
            keyHash: String,
        ): Boolean {
            val choice = state.choices[keyHash] ?: return false
            return choice.identity == identity &&
                choice.binding == binding &&
                choice.choice == VaultRememberChoice.REMEMBERED
        }

        private fun decryptCurrentRecord(
            record: RememberRecord,
            state: RememberLedger,
            keyHash: String,
        ): VaultUnlockKey? =
            crypto
                .load(record.alias)
                ?.takeIf { key -> record.matches(state, binding) && crypto.isAcceptable(key) && accessAllowed() }
                ?.let { key ->
                    val cipher = Cipher.getInstance(TRANSFORMATION)
                    cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, record.nonce))
                    updateAad(cipher, aadFor(record))
                    val plaintext = cipher.doFinal(record.ciphertext).also { ownedMaterial = it }
                    failpoint(VaultDeviceRememberFailpoint.AFTER_DECRYPTION, plaintext)
                    if (!plaintextStillAllowed(plaintext, record, keyHash)) {
                        plaintext.fill(0)
                        ownedMaterial = null
                        null
                    } else {
                        val validation =
                            RememberValidation(
                                record.identity,
                                record.binding,
                                record.globalEpoch,
                                record.accountEpoch,
                                record.identityEpoch,
                                record.alias,
                            )
                        VaultUnlockKey(plaintext) { recordStillCurrent(validation, permit) }
                            .also { candidate = it }
                    }
                }

        private fun plaintextStillAllowed(
            plaintext: ByteArray,
            record: RememberRecord,
            keyHash: String,
        ): Boolean {
            if (plaintext.size != KEY_MATERIAL_BYTES || !accessAllowed()) return false
            val after = readLedger()
            return record.matches(after, binding) &&
                after.choices[keyHash]?.choice == VaultRememberChoice.REMEMBERED
        }

        private fun accessAllowed(): Boolean =
            !askEveryTime() && isSupported() && deviceAllowedNow() && safePermit(permit)

        private fun aadFor(record: RememberRecord) =
            RememberAad(
                identity,
                binding,
                record.globalEpoch,
                record.accountEpoch,
                record.identityEpoch,
                record.alias,
                record.nonce,
            )
    }

    fun choice(identity: VaultIdentity): VaultRememberChoice? =
        guarded {
            withLedgerLock { readLedger().choices[identityHash(identity)]?.takeIf { it.identity == identity }?.choice }
        }

    fun hasRemembered(identity: VaultIdentity): Boolean =
        runCatching {
            withLedgerLock {
                val state = readLedger()
                val item = state.choices[identityHash(identity)] ?: return@withLedgerLock false
                val record = readRecord(identity) ?: return@withLedgerLock false
                try {
                    matchesRememberedRecord(item, record, identity, state)
                } finally {
                    record.clear()
                }
            }
        }.getOrDefault(false)

    private fun matchesRememberedRecord(
        item: ChoiceRecord,
        record: RememberRecord,
        identity: VaultIdentity,
        state: RememberLedger,
    ): Boolean =
        item.identity == identity &&
            item.choice == VaultRememberChoice.REMEMBERED &&
            item.binding?.let { record.matches(state, it) } == true

    fun decline(identity: VaultIdentity) =
        guarded {
            withLedgerLock {
                val state = readLedger()
                val hash = identityHash(identity)
                val epoch = (state.identityEpochs[hash] ?: 0L) + 1L
                writeLedger(
                    state.copy(
                        identityEpochs = state.identityEpochs + (hash to epoch),
                        choices = state.choices + (hash to ChoiceRecord(identity, null, VaultRememberChoice.DECLINED)),
                    ),
                )
                val old = runCatching { readRecordAlias(identity) }.getOrNull()
                deleteRecord(identity)
                deleteAliases(identity, old)
            }
        }

    fun resetChoice(identity: VaultIdentity) = forget(identity)

    fun identities(): List<VaultIdentity> =
        guarded {
            withLedgerLock {
                readLedger()
                    .choices.values
                    .map { it.identity }
                    .distinct()
                    .sortedBy { identityHash(it) }
            }
        }

    fun forget(identity: VaultIdentity) =
        guarded {
            withLedgerLock {
                val state = readLedger()
                val hash = identityHash(identity)
                writeLedger(
                    state.copy(
                        identityEpochs = state.identityEpochs + (hash to ((state.identityEpochs[hash] ?: 0L) + 1L)),
                        choices = state.choices - hash,
                    ),
                )
                val old = runCatching { readRecordAlias(identity) }.getOrNull()
                deleteRecord(identity)
                deleteAliases(identity, old)
            }
        }

    fun forgetAccount(accountId: String) = revokeAccountAnd(accountId) {}

    /** Fence remember/restore while an explicit credential replacement/removal commits. */
    internal fun <T> revokeAccountAnd(
        accountId: String,
        action: () -> T,
    ): T =
        guarded {
            require(accountId.isNotBlank())
            withLedgerLock {
                val state = readLedger()
                val targets =
                    (
                        state.choices.values
                            .filter { it.identity.accountId == accountId }
                            .map { it.identity } +
                            listRecordFiles().mapNotNull { file ->
                                runCatching {
                                    readRecordIdentity(
                                        file,
                                    )
                                }.getOrNull()?.takeIf { it.accountId == accountId }
                            }
                    ).distinct()
                val nextEpoch = (state.accountEpochs[accountId] ?: 0L) + 1L
                writeLedger(
                    state.copy(
                        accountEpochs = state.accountEpochs + (accountId to nextEpoch),
                        choices =
                            state.choices.filterValues {
                                it.identity.accountId !=
                                    accountId
                            },
                    ),
                )
                targets.forEach { identity ->
                    val alias = runCatching { readRecordAlias(identity) }.getOrNull()
                    deleteRecord(identity)
                    deleteAliases(identity, alias)
                }
                action()
            }
        }

    fun forgetAll() =
        guarded {
            withLedgerLock {
                val state = readLedger()
                writeLedger(state.copy(globalEpoch = state.globalEpoch + 1L, choices = emptyMap()))
                cleanupOwnedRecordsLocked()
            }
        }

    private fun cleanupOwnedRecordsLocked() {
        listRecordFiles().forEach { file ->
            val record = runCatching { readRecordFile(file) }.getOrNull()
            if (record != null) {
                try {
                    deleteRecord(record.identity)
                    deleteAliases(record.identity, record.alias)
                } finally {
                    record.clear()
                }
            } else {
                disk.deletePartialRecordFile(file)
            }
        }
        deleteAllOwnedAliases()
    }

    private fun recordStillCurrent(
        validation: RememberValidation,
        permit: () -> Boolean,
    ): Boolean =
        runCatching {
            !askEveryTime() &&
                isSupported() &&
                deviceAllowedNow() &&
                safePermit(permit) &&
                withLedgerLock {
                    val state = readLedger()
                    validation.matches(state, validation.binding) &&
                        state.choices[identityHash(validation.identity)]?.let {
                            it.identity == validation.identity &&
                                it.binding == validation.binding &&
                                it.choice == VaultRememberChoice.REMEMBERED
                        } == true &&
                        readRecordAlias(validation.identity) == validation.alias
                }
        }.getOrDefault(false)

    private fun stillAllowed(permit: () -> Boolean): Boolean =
        !askEveryTime() && isSupported() && deviceAllowedNow() && safePermit(permit)

    private fun deviceAllowedNow(): Boolean = runCatching(deviceAllowed).getOrDefault(false)

    private fun grantCurrent(
        grant: VaultDeviceRememberGrant,
        identity: VaultIdentity,
        state: RememberLedger,
    ): Boolean =
        grant.storeId == storeId() &&
            grant.identityHash == identityHash(identity) &&
            grant.globalEpoch == state.globalEpoch &&
            grant.accountEpoch == (state.accountEpochs[identity.accountId] ?: 0L) &&
            grant.identityEpoch == (state.identityEpochs[grant.identityHash] ?: 0L)

    private fun safePermit(permit: () -> Boolean): Boolean = runCatching(permit).getOrDefault(false)

    private fun <T> guarded(block: () -> T): T =
        try {
            block()
        } catch (error: VaultDeviceRememberOutcomeUnknownException) {
            throw error
        } catch (error: GeneralSecurityException) {
            throw VaultDeviceRememberException(error)
        } catch (error: IOException) {
            throw VaultDeviceRememberException(error)
        } catch (error: IllegalStateException) {
            throw VaultDeviceRememberException(error)
        } catch (error: IllegalArgumentException) {
            throw VaultDeviceRememberException(error)
        } catch (error: SecurityException) {
            throw VaultDeviceRememberException(error)
        } catch (error: ProviderException) {
            throw VaultDeviceRememberException(error)
        }

    private fun <T> withLedgerLock(block: () -> T): T = disk.withLock(block)

    private fun readLedger(): RememberLedger = disk.readLedger()

    private fun writeLedger(ledger: RememberLedger) = disk.writeLedger(ledger)

    private fun readRecord(identity: VaultIdentity): RememberRecord? = disk.readRecord(identity)

    private fun readRecordAlias(identity: VaultIdentity): String? = disk.readRecordAlias(identity)

    private fun readRecordIdentity(file: File): VaultIdentity? = disk.readRecordIdentity(file)

    private fun readRecordFile(file: File): RememberRecord? = disk.readRecordFile(file)

    private fun writeRecord(
        identity: VaultIdentity,
        record: RememberRecord,
    ) = disk.writeRecord(identity, record)

    private fun deleteRecord(identity: VaultIdentity) = disk.deleteRecord(identity)

    private fun listRecordFiles(): List<File> = disk.listRecordFiles()

    private fun storeId(): String =
        directory.canonicalFile
            .toPath()
            .normalize()
            .toString()

    private fun identityHash(identity: VaultIdentity): String {
        val bytes = identity.encoded
        return try {
            bytes.sha256Hex()
        } finally {
            bytes.fill(0)
        }
    }

    private fun aliasPrefix(identity: VaultIdentity): String = "$ALIAS_PREFIX${identityHash(identity)}_"

    private fun cleanupNewEnrollment(
        identity: VaultIdentity,
        alias: String,
        keyCreated: Boolean,
        recordWritten: Boolean,
    ): Boolean {
        val aliasRemoved = !keyCreated || runCleanup { deleteAliasForIdentity(identity, alias) }
        val recordRemoved = !recordWritten || runCleanup { deleteRecord(identity) }
        return aliasRemoved && recordRemoved
    }

    private fun runCleanup(action: () -> Unit): Boolean =
        try {
            action()
            true
        } catch (_: GeneralSecurityException) {
            false
        } catch (_: IOException) {
            false
        } catch (_: IllegalStateException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        } catch (_: SecurityException) {
            false
        } catch (_: ProviderException) {
            false
        }

    private fun deleteAliases(
        identity: VaultIdentity,
        recordedAlias: String?,
    ) {
        val prefix = "$ALIAS_PREFIX${identityHash(identity)}_"
        val pattern = Regex("${Regex.escape(prefix)}[0-9a-f]{16}")
        val aliases = crypto.aliases().filter(pattern::matches).toMutableSet()
        recordedAlias?.takeIf(pattern::matches)?.let(aliases::add)
        aliases.forEach(crypto::delete)
        check(crypto.aliases().none(pattern::matches)) { "Device remember alias cleanup is incomplete." }
    }

    private fun deleteAliasForIdentity(
        identity: VaultIdentity,
        alias: String,
    ) {
        val prefix = "$ALIAS_PREFIX${identityHash(identity)}_"
        if (alias.matches(Regex("${Regex.escape(prefix)}[0-9a-f]{16}"))) {
            crypto.delete(alias)
            check(alias !in crypto.aliases()) { "Device remember alias cleanup is incomplete." }
        }
    }

    private fun deleteAllOwnedAliases() {
        val pattern = Regex("${Regex.escape(ALIAS_PREFIX)}[0-9a-f]{64}_[0-9a-f]{16}")
        crypto.aliases().filter(pattern::matches).forEach(crypto::delete)
        check(crypto.aliases().none(pattern::matches)) { "Device remember alias cleanup is incomplete." }
    }

    private fun updateAad(
        cipher: Cipher,
        associatedData: RememberAad,
    ) {
        val bytes = aad(associatedData)
        try {
            cipher.updateAAD(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    companion object {
        private const val DIRECTORY = "vault-device-remember-v1"
        private const val ALIAS_PREFIX = "raiun_vault_device_v1_"
        private const val KEY_MATERIAL_BYTES = 80
        private const val NONCE_BYTES = 12
        private const val GCM_TAG_BITS = 128
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val random = SecureRandom()
        private val MAGIC = byteArrayOf(0x52, 0x44, 0x56, 0x31)

        private fun randomHex(size: Int): String =
            ByteArray(size / 2).also(random::nextBytes).joinToString("") {
                "%02x".format(it)
            }

        private fun ByteArray.sha256Hex(): String =
            MessageDigest.getInstance("SHA-256").digest(this).joinToString("") {
                "%02x".format(it)
            }

        private fun aad(context: RememberAad): ByteArray =
            ByteArrayOutputStream().use { bytes ->
                DataOutputStream(bytes).use { out ->
                    out.write(MAGIC)
                    val identityBytes = context.identity.associatedData
                    out.writeInt(identityBytes.size)
                    out.write(identityBytes)
                    identityBytes.fill(0)
                    out.writeUTF(context.binding.incarnation)
                    out.writeUTF(context.binding.accountDigest)
                    out.writeLong(context.globalEpoch)
                    out.writeLong(context.accountEpoch)
                    out.writeLong(context.identityEpoch)
                    out.writeUTF(context.alias)
                    out.writeInt(context.nonce.size)
                    out.write(context.nonce)
                }
                bytes.toByteArray()
            }
    }
}

class VaultDeviceRememberException(
    cause: Throwable? = null,
) : IllegalStateException("Device remember data is unavailable.", cause)

/** Enrollment cleanup could not be confirmed; the UI must not report that remembering succeeded. */
class VaultDeviceRememberOutcomeUnknownException :
    IllegalStateException(
        "Device remember could not be finalized safely. Reset this vault's phone-remember choice before retrying.",
    )
