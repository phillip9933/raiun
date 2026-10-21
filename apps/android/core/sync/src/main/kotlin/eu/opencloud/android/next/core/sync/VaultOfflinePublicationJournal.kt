package eu.opencloud.android.next.core.sync

import android.util.AtomicFile
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.util.UUID

/** Crash recovery contains only prior encrypted metadata, public root identity and opaque identifiers. */
internal data class VaultOfflinePublicationJournal(
    val transferId: String,
    val blobId: String,
    val previousBlobId: String?,
    val locationDescriptor: ByteArray,
    val previousManifest: ByteArray?,
    val previousCatalog: ByteArray?,
) {
    @Suppress("TooGenericExceptionCaught") // AtomicFile must roll back every failed journal write.
    fun write(directory: File) =
        vaultJobWrite {
            requireSafePublicationDirectory(directory)
            validateId(transferId)
            validateId(blobId)
            previousBlobId?.let(::validateId)
            val file = File(directory, FILE_NAME)
            check(
                !java.nio.file.Files
                    .isSymbolicLink(file.toPath()),
            )
            check(
                !java.nio.file.Files
                    .isSymbolicLink(File(directory, "$FILE_NAME.bak").toPath()),
            )
            val atomic = AtomicFile(file)
            val output = atomic.startWrite()
            try {
                DataOutputStream(output).apply {
                    writeInt(1)
                    writeUTF(transferId)
                    writeUTF(blobId)
                    writeBoolean(previousBlobId != null)
                    previousBlobId?.let(::writeUTF)
                    writeBytes(locationDescriptor, MAX_CATALOG)
                    writeNullableBytes(previousManifest, MAX_MANIFEST)
                    writeNullableBytes(previousCatalog, MAX_CATALOG)
                    flush()
                }
                atomic.finishWrite(output)
            } catch (failure: Exception) {
                atomic.failWrite(output)
                throw failure
            }
        }

    fun restore(directory: File) =
        vaultJobWrite {
            requireSafePublicationDirectory(directory)
            restoreMetadata(File(directory, "manifest.enc"), previousManifest)
            restoreMetadata(File(directory, "root.json"), previousCatalog)
        }

    fun finish(
        directory: File,
        accepted: Boolean,
    ) = vaultJobWrite {
        requireSafePublicationDirectory(directory)
        val blobs = File(directory, "blobs")
        check(
            !java.nio.file.Files
                .isSymbolicLink(blobs.toPath()),
        )
        val discard = if (accepted) previousBlobId?.takeUnless { it == blobId } else blobId
        if (discard != null) {
            val blob = File(blobs, discard)
            vaultJobRequireWrite(deleteVaultJobTree(blob))
        }
        val journal = File(directory, FILE_NAME)
        AtomicFile(journal).delete()
        vaultJobRequireWrite(!journal.exists() && !File(directory, "$FILE_NAME.bak").exists())
    }

    companion object {
        private const val FILE_NAME = "publication.pending"
        private const val MAX_MANIFEST = 16 * 1024 * 1024 + 32
        private const val MAX_CATALOG = 64 * 1024
        private const val MAX_JOURNAL = MAX_MANIFEST + 2 * MAX_CATALOG + 512

        fun read(directory: File): VaultOfflinePublicationJournal? =
            vaultJobRead {
                requireSafePublicationDirectory(directory)
                val file = File(directory, FILE_NAME)
                if (!file.exists() && !File(directory, "$FILE_NAME.bak").exists()) return@vaultJobRead null
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(file.toPath()),
                )
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(File(directory, "$FILE_NAME.bak").toPath()),
                )
                AtomicFile(file).openRead().use { stream ->
                    check(file.length() in 1..MAX_JOURNAL)
                    DataInputStream(stream).use { input ->
                        check(input.readInt() == 1)
                        val journal =
                            VaultOfflinePublicationJournal(
                                input.readUTF().also(::validateId),
                                input.readUTF().also(::validateId),
                                if (input.readBoolean()) input.readUTF().also(::validateId) else null,
                                input.readBytes(MAX_CATALOG),
                                input.readNullableBytes(MAX_MANIFEST),
                                input.readNullableBytes(MAX_CATALOG),
                            )
                        check(input.read() == -1)
                        journal
                    }
                }
            }
    }
}

private fun validateId(id: String) {
    require(UUID.fromString(id).toString() == id)
}

private fun DataOutputStream.writeBytes(
    bytes: ByteArray,
    maximum: Int,
) {
    require(bytes.size <= maximum)
    writeInt(bytes.size)
    write(bytes)
}

private fun DataOutputStream.writeNullableBytes(
    bytes: ByteArray?,
    maximum: Int,
) {
    if (bytes == null) writeInt(-1) else writeBytes(bytes, maximum)
}

private fun DataInputStream.readBytes(maximum: Int): ByteArray {
    val size = readInt()
    check(size in 0..maximum)
    return ByteArray(size).also(::readFully)
}

private fun DataInputStream.readNullableBytes(maximum: Int): ByteArray? {
    val size = readInt()
    if (size == -1) return null
    check(size in 0..maximum)
    return ByteArray(size).also(::readFully)
}

@Suppress("TooGenericExceptionCaught") // AtomicFile must roll back every failed journal write.
private fun restoreMetadata(file: File, bytes: ByteArray?) {
    check(
        !java.nio.file.Files
            .isSymbolicLink(file.toPath()),
    )
    check(
        !java.nio.file.Files
            .isSymbolicLink(File(file.parentFile, "${file.name}.bak").toPath()),
    )
    val atomic = AtomicFile(file)
    if (bytes == null) {
        atomic.delete()
        vaultJobRequireWrite(!file.exists() && !File(file.parentFile, "${file.name}.bak").exists())
        return
    }
    val output = atomic.startWrite()
    try {
        output.write(bytes)
        atomic.finishWrite(output)
    } catch (failure: Exception) {
        atomic.failWrite(output)
        throw failure
    }
}

private fun requireSafePublicationDirectory(directory: File) {
    listOfNotNull(directory, directory.parentFile, directory.parentFile?.parentFile).forEach {
        check(
            !java.nio.file.Files
                .isSymbolicLink(it.toPath()),
        )
    }
}
