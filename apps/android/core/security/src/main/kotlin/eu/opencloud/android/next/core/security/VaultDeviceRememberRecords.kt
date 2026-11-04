package eu.opencloud.android.next.core.security

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException

internal data class ChoiceRecord(
    val identity: VaultIdentity,
    val binding: VaultRememberBinding?,
    val choice: VaultRememberChoice,
)

internal data class RememberLedger(
    val globalEpoch: Long = 0,
    val accountEpochs: Map<String, Long> = emptyMap(),
    val identityEpochs: Map<String, Long> = emptyMap(),
    val choices: Map<String, ChoiceRecord> = emptyMap(),
) {
    fun encode(): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.writeInt(MAGIC)
                out.writeInt(VERSION)
                out.writeLong(globalEpoch)
                writeLongMap(out, accountEpochs)
                writeLongMap(out, identityEpochs)
                writeChoices(out, choices)
            }
            bytes.toByteArray()
        }

    companion object {
        private const val MAGIC = 0x52444c31
        private const val VERSION = 1
        private const val MAX_ENTRIES = 50_000

        fun decode(bytes: ByteArray): RememberLedger =
            try {
                DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                    require(input.readInt() == MAGIC && input.readInt() == VERSION)
                    val global = input.readLong().also { require(it >= 0) }
                    val accounts = readLongMap(input, accountMap = true)
                    val identityEpochs = readLongMap(input, accountMap = false)
                    val count = input.readInt().also { require(it in 0..MAX_ENTRIES) }
                    val choices =
                        buildMap {
                            repeat(count) {
                                val hash = input.readUTF().also { require(it.matches(Regex("[0-9a-f]{64}"))) }
                                val identity = readIdentity(input)
                                val choice =
                                    VaultRememberChoice.entries.getOrNull(input.readUnsignedByte())
                                        ?: error("invalid choice")
                                val binding = if (input.readBoolean()) readBinding(input) else null
                                require((choice == VaultRememberChoice.REMEMBERED) == (binding != null))
                                require(hash == identity.hashForRemember())
                                require(put(hash, ChoiceRecord(identity, binding, choice)) == null)
                            }
                        }
                    require(input.available() == 0)
                    RememberLedger(global, accounts, identityEpochs, choices)
                }
            } catch (error: IOException) {
                throw VaultDeviceRememberException(error)
            } catch (error: IllegalArgumentException) {
                throw VaultDeviceRememberException(error)
            } catch (error: IllegalStateException) {
                throw VaultDeviceRememberException(error)
            }

        private fun writeChoices(
            out: DataOutputStream,
            choices: Map<String, ChoiceRecord>,
        ) {
            out.writeInt(choices.size)
            choices.toSortedMap().forEach { (hash, item) -> writeChoice(out, hash, item) }
        }

        private fun writeChoice(
            out: DataOutputStream,
            hash: String,
            item: ChoiceRecord,
        ) {
            out.writeUTF(hash)
            writeIdentity(out, item.identity)
            out.writeByte(item.choice.ordinal)
            out.writeBoolean(item.binding != null)
            item.binding?.let { writeBinding(out, it) }
        }

        private fun writeLongMap(
            out: DataOutputStream,
            values: Map<String, Long>,
        ) {
            out.writeInt(values.size)
            values.toSortedMap().forEach { (key, value) ->
                out.writeUTF(key)
                out.writeLong(value)
            }
        }

        private fun readLongMap(
            input: DataInputStream,
            accountMap: Boolean,
        ): Map<String, Long> {
            val count = input.readInt().also { require(it in 0..MAX_ENTRIES) }
            return buildMap {
                repeat(count) {
                    val key = input.readUTF()
                    if (accountMap) {
                        require(key.isNotBlank() && key.length <= 4096)
                    } else {
                        require(key.matches(Regex("[0-9a-f]{64}")))
                    }
                    val value = input.readLong().also { require(it >= 0) }
                    require(put(key, value) == null)
                }
            }
        }
    }
}

internal data class RememberRecord(
    val identity: VaultIdentity,
    val binding: VaultRememberBinding,
    val globalEpoch: Long,
    val accountEpoch: Long,
    val identityEpoch: Long,
    val alias: String,
    val nonce: ByteArray,
    val ciphertext: ByteArray,
) {
    fun matches(
        state: RememberLedger,
        requestedBinding: VaultRememberBinding,
    ): Boolean =
        binding == requestedBinding &&
            globalEpoch == state.globalEpoch &&
            accountEpoch == (state.accountEpochs[identity.accountId] ?: 0L) &&
            identityEpoch == (state.identityEpochs[identity.hashForRemember()] ?: 0L)

    fun clear() {
        nonce.fill(0)
        ciphertext.fill(0)
    }

    fun encode(): ByteArray =
        ByteArrayOutputStream().use { bytes ->
            DataOutputStream(bytes).use { out ->
                out.writeInt(MAGIC)
                out.writeInt(VERSION)
                writeIdentity(out, identity)
                writeBinding(out, binding)
                out.writeLong(globalEpoch)
                out.writeLong(accountEpoch)
                out.writeLong(identityEpoch)
                out.writeUTF(alias)
                out.writeInt(nonce.size)
                out.write(nonce)
                out.writeInt(ciphertext.size)
                out.write(ciphertext)
            }
            bytes.toByteArray()
        }

    companion object {
        private const val MAGIC = 0x52445231
        private const val VERSION = 1

        fun decode(bytes: ByteArray): RememberRecord =
            try {
                DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                    require(input.readInt() == MAGIC && input.readInt() == VERSION)
                    val identity = readIdentity(input)
                    val binding = readBinding(input)
                    val global = input.readLong().also { require(it >= 0) }
                    val account = input.readLong().also { require(it >= 0) }
                    val identityEpoch = input.readLong().also { require(it >= 0) }
                    val alias =
                        input.readUTF().also {
                            require(
                                it.matches(Regex("raiun_vault_device_v1_[0-9a-f]{64}_[0-9a-f]{16}")),
                            )
                        }
                    val nonce = readBytes(input, 12, 12)
                    val ciphertext = readBytes(input, 96, 96)
                    require(input.available() == 0)
                    RememberRecord(identity, binding, global, account, identityEpoch, alias, nonce, ciphertext)
                }
            } catch (error: IOException) {
                throw VaultDeviceRememberException(error)
            } catch (error: IllegalArgumentException) {
                throw VaultDeviceRememberException(error)
            } catch (error: IllegalStateException) {
                throw VaultDeviceRememberException(error)
            }
    }
}

/** Immutable predicate input retained after encrypted record buffers are wiped. */
internal data class RememberValidation(
    val identity: VaultIdentity,
    val binding: VaultRememberBinding,
    val globalEpoch: Long,
    val accountEpoch: Long,
    val identityEpoch: Long,
    val alias: String,
) {
    fun matches(
        state: RememberLedger,
        requestedBinding: VaultRememberBinding,
    ): Boolean =
        binding == requestedBinding &&
            globalEpoch == state.globalEpoch &&
            accountEpoch == (state.accountEpochs[identity.accountId] ?: 0L) &&
            identityEpoch == (state.identityEpochs[identity.hashForRemember()] ?: 0L)
}

internal fun writeIdentity(
    out: DataOutputStream,
    identity: VaultIdentity,
) {
    out.writeUTF(identity.accountId)
    out.writeUTF(identity.canonicalServer)
    out.writeUTF(identity.driveId)
    out.writeUTF(identity.remoteVaultId)
}

internal fun readIdentity(input: DataInputStream): VaultIdentity =
    VaultIdentity(input.readUTF(), input.readUTF(), input.readUTF(), input.readUTF())

internal fun writeBinding(
    out: DataOutputStream,
    binding: VaultRememberBinding,
) {
    out.writeUTF(binding.incarnation)
    out.writeUTF(binding.accountDigest)
}

internal fun readBinding(input: DataInputStream): VaultRememberBinding =
    VaultRememberBinding(input.readUTF(), input.readUTF())

internal fun readBytes(
    input: DataInputStream,
    min: Int,
    max: Int,
): ByteArray {
    val size = input.readInt().also { require(it in min..max) }
    return ByteArray(size).also(input::readFully)
}

internal fun VaultIdentity.hashForRemember(): String {
    val bytes = encoded
    return try {
        java.security.MessageDigest
            .getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }
    } finally {
        bytes.fill(0)
    }
}
