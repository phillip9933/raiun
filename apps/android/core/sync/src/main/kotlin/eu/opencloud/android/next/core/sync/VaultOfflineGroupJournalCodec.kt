package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupPublication
import java.io.DataInputStream
import java.io.DataOutputStream
import java.util.UUID

internal fun DataOutputStream.writeGroupPublication(value: VaultGroupPublication) {
    validateGroupPublication(value)
    writeUTF(value.publicationId)
    writeUTF(value.groupId)
    writeGroupText(value.owner.accountId)
    writeUTF(value.owner.incarnation)
    writeUTF(value.owner.accountIdentityDigest)
    writeUTF(value.identityDigest)
    writeUTF(value.descriptorDigest)
    writeUTF(value.planDigest)
    writeLong(value.memberCount)
    writeUTF(value.baseRootDigest)
    writeUTF(value.nextRootDigest)
}

internal fun DataInputStream.readGroupPublication(): VaultGroupPublication =
    VaultGroupPublication(
        readUTF(),
        readUTF(),
        VaultGroupOwner(readGroupText(), readUTF(), readUTF()),
        readUTF(),
        readUTF(),
        readUTF(),
        readLong(),
        readUTF(),
        readUTF(),
    ).also(::validateGroupPublication)

private fun DataOutputStream.writeGroupText(value: String) {
    val bytes = value.toByteArray(Charsets.UTF_8)
    require(bytes.size <= 64 * 1024 && VaultOfflineIndexCodec.text(bytes) == value)
    writeInt(bytes.size)
    write(bytes)
}

private fun DataInputStream.readGroupText(): String {
    val size = readInt()
    require(size in 0..64 * 1024)
    return VaultOfflineIndexCodec.text(ByteArray(size).also(::readFully))
}

private fun validateGroupPublication(value: VaultGroupPublication) {
    require(UUID.fromString(value.publicationId).toString() == value.publicationId)
    require(UUID.fromString(value.groupId).toString() == value.groupId)
    require(value.owner.incarnation.matches(Regex("[a-f0-9]{32}")))
    require(value.owner.accountId.isNotBlank() && value.memberCount >= 1)
    listOf(
        value.owner.accountIdentityDigest,
        value.identityDigest,
        value.descriptorDigest,
        value.planDigest,
        value.baseRootDigest,
        value.nextRootDigest,
    ).forEach { require(it.matches(Regex("[a-f0-9]{64}"))) }
}
