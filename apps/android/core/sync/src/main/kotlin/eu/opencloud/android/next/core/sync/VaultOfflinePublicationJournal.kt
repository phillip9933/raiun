package eu.opencloud.android.next.core.sync

import android.util.AtomicFile
import eu.opencloud.android.next.core.database.VaultGroupPublication
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Prior encrypted metadata and exact opaque publication ownership; no plaintext names or keys. */
internal data class VaultOfflinePublicationJournal(
    val publicationId: String,
    val blobId: String,
    val previousBlobId: String?,
    val locationDescriptor: ByteArray,
    val previousManifest: ByteArray?,
    val previousCatalog: ByteArray?,
    val nextManifestDigest: String? = null,
    // null = legacy/Room transfer authority, false = local prepared, true = durable local commit receipt.
    val localCommitted: Boolean? = null,
    val groupPublication: VaultGroupPublication? = null,
) {
    fun write(
        directory: File,
        durability: OfflineDurability = OfflineDurability(directory),
    ) = vaultJobWrite {
        requireSafePublicationDirectory(directory)
        validateId(publicationId)
        validateId(blobId)
        previousBlobId?.let(::validateId)
        val version =
            when {
                groupPublication != null -> 4
                localCommitted != null -> 3
                nextManifestDigest != null -> 2
                else -> 1
            }
        require(version < 3 || nextManifestDigest != null)
        validateGroupBinding()
        val bytes =
            ByteArrayOutputStream().use { buffer ->
                DataOutputStream(buffer).use { output ->
                    output.writeInt(version)
                    output.writeUTF(publicationId)
                    output.writeUTF(blobId)
                    output.writeBoolean(previousBlobId != null)
                    previousBlobId?.let(output::writeUTF)
                    output.writeBytes(locationDescriptor, MAX_CATALOG)
                    output.writeNullableBytes(previousManifest, MAX_MANIFEST)
                    output.writeNullableBytes(previousCatalog, MAX_CATALOG)
                    if (version >= 2) output.writeUTF(requireNotNull(nextManifestDigest).also(::validateDigest))
                    if (version == 3) output.writeBoolean(requireNotNull(localCommitted))
                    if (version == 4) output.writeGroupPublication(requireNotNull(groupPublication))
                }
                buffer.toByteArray()
            }
        durability.writeAtomic(File(directory, FILE_NAME), bytes)
    }

    fun commitLocal(
        directory: File,
        durability: OfflineDurability = OfflineDurability(directory),
    ) {
        check(localCommitted == false && groupPublication == null)
        requireOwnedPointer(directory, accepted = true)
        copy(localCommitted = true).write(directory, durability)
    }

    fun restore(
        directory: File,
        durability: OfflineDurability = OfflineDurability(directory),
    ) = vaultJobWrite {
        requireSafePublicationDirectory(directory)
        if (nextManifestDigest != null) {
            val current = publicationRootDigest(directory)
            if (current != nextManifestDigest &&
                current != previousDigest()
            ) {
                throw OpenCloudException(OpenCloudError.DownloadIntegrity)
            }
        }
        restoreMetadata(File(directory, "manifest.enc"), previousManifest, durability)
        restoreMetadata(File(directory, "root.json"), previousCatalog, durability)
    }

    fun finish(
        directory: File,
        accepted: Boolean,
        durability: OfflineDurability = OfflineDurability(directory),
    ) = vaultJobWrite {
        requireSafePublicationDirectory(directory)
        requireOwnedPointer(directory, accepted)
        // Authenticated reachability plus live reader guards own blob deletion, never this receipt alone.
        durability.deleteAtomic(File(directory, FILE_NAME))
    }

    private fun requireOwnedPointer(
        directory: File,
        accepted: Boolean,
    ) {
        if (nextManifestDigest == null) return // v1 recovery remains compatible with its original pointer format.
        val expected = if (accepted) nextManifestDigest else previousDigest()
        if (publicationRootDigest(directory) != expected) throw OpenCloudException(OpenCloudError.DownloadIntegrity)
    }

    private fun validateGroupBinding() {
        val group = groupPublication ?: return
        require(localCommitted == null && group.publicationId == publicationId)
        require(group.nextRootDigest == nextManifestDigest && group.baseRootDigest == previousDigest())
    }

    private fun previousDigest(): String? =
        previousManifest?.let {
            MessageDigest.getInstance("SHA-256").digest(it).joinToString("") { byte -> "%02x".format(byte) }
        }

    companion object {
        private const val FILE_NAME = "publication.pending"
        private const val MAX_MANIFEST = 16 * 1024 * 1024 + 32
        private const val MAX_CATALOG = 64 * 1024
        private const val MAX_JOURNAL = MAX_MANIFEST + 3 * MAX_CATALOG + 4096

        fun read(directory: File): VaultOfflinePublicationJournal? =
            vaultJobRead {
                requireSafePublicationDirectory(directory)
                val file = File(directory, FILE_NAME)
                if (!file.exists() && !File(file.path + ".bak").exists()) return@vaultJobRead null
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(file.toPath()),
                )
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(File(file.path + ".bak").toPath()),
                )
                AtomicFile(file).openRead().use { stream ->
                    check(file.length() in 1..MAX_JOURNAL)
                    DataInputStream(stream).use { input -> decode(input) }
                }
            }

        private fun decode(input: DataInputStream): VaultOfflinePublicationJournal {
            val version = input.readInt()
            check(version in 1..4)
            val journal =
                VaultOfflinePublicationJournal(
                    input.readUTF().also(::validateId),
                    input.readUTF().also(::validateId),
                    if (input.readBoolean()) input.readUTF().also(::validateId) else null,
                    input.readBytes(MAX_CATALOG),
                    input.readNullableBytes(MAX_MANIFEST),
                    input.readNullableBytes(MAX_CATALOG),
                    if (version >= 2) input.readUTF().also(::validateDigest) else null,
                    if (version == 3) input.readBoolean() else null,
                    if (version == 4) input.readGroupPublication() else null,
                )
            check(input.read() == -1)
            journal.validateGroupBinding()
            return journal
        }
    }
}

private fun validateDigest(value: String) {
    require(value.matches(Regex("[a-f0-9]{64}")))
}

private fun publicationRootDigest(directory: File): String? {
    val file = File(directory, "manifest.enc")
    if (!file.exists() && !File(file.path + ".bak").exists()) return null
    check(
        !java.nio.file.Files
            .isSymbolicLink(file.toPath()),
    )
    return AtomicFile(file).openRead().use(::digestPublicationRoot)
}

private fun digestPublicationRoot(input: java.io.InputStream): String {
    val digest = java.security.MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(64 * 1024)
    var count = 0L
    try {
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            count += read
            check(count <= 16L * 1024 * 1024 + 32)
            digest.update(buffer, 0, read)
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    } finally {
        buffer.fill(0)
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

private fun restoreMetadata(
    file: File,
    bytes: ByteArray?,
    durability: OfflineDurability,
) {
    if (bytes == null) durability.deleteAtomic(file) else durability.writeAtomic(file, bytes)
}

private fun requireSafePublicationDirectory(directory: File) {
    listOfNotNull(directory, directory.parentFile, directory.parentFile?.parentFile).forEach {
        check(
            !java.nio.file.Files
                .isSymbolicLink(it.toPath()),
        )
    }
}

/** Enumerates only private account/vault directories; the Store retains all identity and recovery decisions. */
internal suspend fun scanOfflinePublications(
    root: File,
    account: File?,
    directoryLock: (File) -> kotlinx.coroutines.sync.Mutex,
    consume: suspend (File, VaultOfflinePublicationJournal) -> Unit,
) {
    check(
        !java.nio.file.Files
            .isSymbolicLink(root.toPath()),
    )
    if (account != null) {
        scanOfflineAccountPublications(account, directoryLock, consume)
    } else if (root.isDirectory) {
        java.nio.file.Files.newDirectoryStream(root.toPath()).use { accounts ->
            for (path in accounts) scanOfflineAccountPublications(path.toFile(), directoryLock, consume)
        }
    }
}

private suspend fun scanOfflineAccountPublications(
    account: File,
    directoryLock: (File) -> kotlinx.coroutines.sync.Mutex,
    consume: suspend (File, VaultOfflinePublicationJournal) -> Unit,
) {
    check(
        !java.nio.file.Files
            .isSymbolicLink(account.toPath()),
    )
    if (!account.isDirectory) return
    java.nio.file.Files.newDirectoryStream(account.toPath()).use { directories ->
        for (path in directories) recoverOfflinePublicationDirectory(path.toFile(), directoryLock, consume)
    }
}

private suspend fun recoverOfflinePublicationDirectory(
    directory: File,
    directoryLock: (File) -> kotlinx.coroutines.sync.Mutex,
    consume: suspend (File, VaultOfflinePublicationJournal) -> Unit,
) {
    check(
        !java.nio.file.Files
            .isSymbolicLink(directory.toPath()),
    )
    if (!directory.isDirectory) return
    val lock = directoryLock(directory)
    lock.lock()
    try {
        val journal = VaultOfflinePublicationJournal.read(directory)
        if (journal != null) consume(directory, journal)
    } finally {
        lock.unlock()
    }
}
