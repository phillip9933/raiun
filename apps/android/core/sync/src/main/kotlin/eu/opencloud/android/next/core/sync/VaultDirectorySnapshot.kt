package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Complete, privately staged directory. Only one bounded page is authorized at a time. */
class VaultDirectorySnapshot internal constructor(
    private val index: VaultDirectoryIndex,
    private val checkCurrent: suspend () -> Unit,
    private val publish: (List<VaultFolder>) -> Unit,
    private val revoke: () -> Unit,
) : AutoCloseable {
    val totalCount: Long = index.count

    suspend fun page(
        offset: Long = 0,
        limit: Int = 128,
    ): List<VaultFolder> {
        var delivered = false
        try {
            val page =
                withContext(Dispatchers.IO) {
                    require(offset >= 0 && limit in 1..256)
                    checkCurrent()
                    val entries = index.page(offset, limit).map { it.copy(leaseId = UUID.randomUUID().toString()) }
                    checkCurrent()
                    publish(entries)
                    entries
                }
            delivered = true
            return page
        } finally {
            if (!delivered) close()
        }
    }

    override fun close() {
        revoke()
        index.close()
    }
}

internal enum class VaultDirectoryOrder { VAULT, DESTINATION }

/**
 * External merge sort with at most 128 decrypted rows and two merge heads in memory.
 * Every on-disk row, including its sort name, is AES-GCM encrypted with a disposable key.
 * Filenames and the random-access offset file contain no child identity or plaintext name.
 * Offsets are not authenticated; ordering/selection rely on the app-private storage boundary.
 */
@Suppress("TooManyFunctions")
internal class VaultDirectoryIndex(
    parent: File,
    private val order: VaultDirectoryOrder = VaultDirectoryOrder.VAULT,
    private var checkActive: () -> Unit,
) : AutoCloseable {
    private val directory = createStage(parent)
    private val key = ByteArray(32).also(SecureRandom()::nextBytes)
    private val random = SecureRandom()
    private val pending = ArrayList<VaultFolder>(128)
    private val levels = ArrayList<File?>()
    private var pendingBytes = 0L
    private var result: File? = null
    private var closed = false
    private val comparator = if (order == VaultDirectoryOrder.DESTINATION) DESTINATION_ORDER else ORDER
    var count: Long = 0
        private set

    @Synchronized
    fun add(entry: VaultFolder) {
        check(!closed && result == null)
        checkActive()
        val bytes = entry.storageBytes()
        if (bytes > MAX_RECORD_BYTES) throw OpenCloudException(OpenCloudError.DirectoryListingTooLarge)
        if (pending.isNotEmpty() && pendingBytes + bytes > MAX_CHUNK_BYTES) flush()
        pending += entry.copy(leaseId = null)
        pendingBytes += bytes
        count++
        if (pending.size == 128) flush()
    }

    @Synchronized
    fun finish() {
        storage {
            check(!closed && result == null)
            flush()
            var merged: File? = null
            // Each carry joins the older left run to the newer right run. Higher occupied
            // levels precede lower levels in wire order, even when byte limits shorten chunks.
            val runs = if (order == VaultDirectoryOrder.DESTINATION) levels.asReversed() else levels
            runs.forEach { run ->
                if (run != null) merged = merged?.let { merge(it, run) } ?: run
            }
            val sorted = merged ?: newFile().also { it.createNewFile() }
            result = sorted
            RandomAccessFile(File(directory, "offsets"), "rw").use { offsets ->
                RandomAccessFile(sorted, "r").use { rows ->
                    var position = 0L
                    while (position < rows.length()) {
                        checkActive()
                        offsets.writeLong(position)
                        rows.seek(position)
                        val length = rows.readInt()
                        requireRecordLength(length)
                        position += 4L + length
                        if (position > rows.length()) invalidIndex()
                    }
                    if (offsets.length() / 8 != count) invalidIndex()
                }
            }
            // The build coroutine is complete after publication; do not retain its cancelled Job.
            checkActive = {}
        }
    }

    @Synchronized
    fun page(
        offset: Long,
        limit: Int,
    ): List<VaultFolder> {
        requireOpen()
        val sorted = result ?: error("Directory has not been validated.")
        if (offset >= count) return emptyList()
        return storage {
            RandomAccessFile(File(directory, "offsets"), "r").use { offsets ->
                RandomAccessFile(sorted, "r").use { rows ->
                    offsets.seek(offset * 8)
                    rows.seek(offsets.readLong())
                    val entries = ArrayList<VaultFolder>(limit)
                    var bytes = 0L
                    while (entries.size < limit && offset + entries.size < count) {
                        checkActive()
                        val entry = read(rows) ?: invalidIndex()
                        bytes += entry.storageBytes()
                        if (entries.isNotEmpty() && bytes > MAX_CHUNK_BYTES) break
                        entries += entry
                    }
                    entries
                }
            }
        }
    }

    @Synchronized
    fun requireOpen() {
        if (closed) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }

    private fun flush() {
        if (pending.isEmpty()) return
        pending.sortWith(comparator)
        var run = newFile()
        storage {
            RandomAccessFile(run, "rw").use { out ->
                pending.forEach {
                    checkActive()
                    write(out, it)
                }
            }
        }
        pending.clear()
        pendingBytes = 0
        var level = 0
        while (true) {
            if (level == levels.size) levels += null
            val previous = levels[level]
            if (previous == null) {
                levels[level] = run
                break
            }
            levels[level] = null
            run = merge(previous, run)
            level++
        }
    }

    private fun merge(
        left: File,
        right: File,
    ): File {
        val merged = newFile()
        storage {
            RandomAccessFile(left, "r").use { a ->
                RandomAccessFile(right, "r").use { b ->
                    RandomAccessFile(merged, "rw").use { out ->
                        var first = read(a)
                        var second = read(b)
                        while (first != null || second != null) {
                            checkActive()
                            if (first != null && (second == null || comparator.compare(first, second) <= 0)) {
                                write(out, first)
                                first = read(a)
                            } else {
                                write(out, requireNotNull(second))
                                second = read(b)
                            }
                        }
                    }
                }
            }
        }
        left.delete()
        right.delete()
        return merged
    }

    private fun write(
        out: RandomAccessFile,
        entry: VaultFolder,
    ) {
        val plain = encode(entry)
        try {
            val nonce = ByteArray(12).also(random::nextBytes)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            val encoded = nonce + cipher.doFinal(plain)
            try {
                out.writeInt(encoded.size)
                out.write(encoded)
            } finally {
                encoded.fill(0)
            }
        } finally {
            plain.fill(0)
        }
    }

    private fun read(input: RandomAccessFile): VaultFolder? {
        if (input.filePointer == input.length()) return null
        val length = input.readInt()
        requireRecordLength(length)
        val encoded = ByteArray(length)
        input.readFully(encoded)
        val plain =
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(
                    Cipher.DECRYPT_MODE,
                    SecretKeySpec(key, "AES"),
                    GCMParameterSpec(128, encoded.copyOfRange(0, 12)),
                )
                cipher.doFinal(encoded, 12, encoded.size - 12)
            } catch (_: java.security.GeneralSecurityException) {
                invalidIndex()
            } finally {
                encoded.fill(0)
            }
        return try {
            decode(plain)
        } finally {
            plain.fill(0)
        }
    }

    private fun encode(entry: VaultFolder): ByteArray {
        val bytes = WipingDirectoryBuffer()
        return try {
            DataOutputStream(bytes).use { out ->
                listOf(
                    entry.id,
                    entry.name,
                    entry.rawName,
                    entry.path,
                    entry.encryptedPath,
                    entry.strongETag.orEmpty(),
                    entry.contentType.orEmpty(),
                ).forEach { value ->
                    out.writeField(value)
                }
                out.writeBoolean(entry.isFolder)
                out.writeLong(entry.size)
                out.writeBoolean(entry.isVaultRoot)
            }
            bytes.toByteArray()
        } finally {
            bytes.wipe()
        }
    }

    private fun DataOutputStream.writeField(value: String) {
        val encoded = value.toByteArray(Charsets.UTF_8)
        try {
            writeInt(encoded.size)
            write(encoded)
        } finally {
            encoded.fill(0)
        }
    }

    private fun decode(bytes: ByteArray): VaultFolder =
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            fun field(): String {
                val length = input.readInt()
                if (length !in 0..MAX_RECORD_BYTES) invalidIndex()
                val encoded = ByteArray(length)
                input.readFully(encoded)
                return try {
                    encoded.toString(Charsets.UTF_8)
                } finally {
                    encoded.fill(0)
                }
            }
            val fields = List(7) { field() }
            val folder = input.readBoolean()
            val size = input.readLong()
            val vaultRoot = input.readBoolean()
            if (input.read() != -1) invalidIndex()
            VaultFolder(
                fields[0],
                fields[1],
                fields[2],
                fields[3],
                fields[4],
                folder,
                size,
                fields[5].takeIf(String::isNotEmpty),
                fields[6].takeIf(String::isNotEmpty),
                isVaultRoot = vaultRoot,
            )
        }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        key.fill(0)
        pending.clear()
        synchronized(processLock) {
            try {
                removeStage(directory)
            } finally {
                activeStages.remove(directory.absolutePath)
            }
        }
    }

    private fun newFile(): File = File(directory, UUID.randomUUID().toString())

    private fun VaultFolder.storageBytes(): Long =
        128L + 4L *
            (
                id.length + name.length + rawName.length + path.length + encryptedPath.length +
                    (strongETag?.length ?: 0) + (contentType?.length ?: 0)
            )

    private inline fun <T> storage(block: () -> T): T =
        try {
            block()
        } catch (_: java.io.IOException) {
            failStorage()
        }

    private fun requireRecordLength(length: Int) {
        if (length !in 28..MAX_RECORD_BYTES + 28) invalidIndex()
    }

    private fun failStorage(): Nothing = throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)

    private fun invalidIndex(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

    private class WipingDirectoryBuffer : ByteArrayOutputStream() {
        fun wipe() = buf.fill(0)
    }

    private companion object {
        const val MAX_RECORD_BYTES = 768 * 1024
        const val MAX_CHUNK_BYTES = 1024 * 1024

        // Android currently uses one app process. Keys and active-stage ownership are never persisted.
        private val processLock = Any()
        private val activeStages = mutableSetOf<String>()
        private val STAGE_NAME = Regex("vault-directory-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

        private fun createStage(parent: File): File =
            synchronized(processLock) {
                val root = validatedParent(parent)
                root.listFiles()?.forEach { previous ->
                    if (isOrphanStage(previous)) removeStage(previous)
                }
                val stage = File(root, "vault-directory-${UUID.randomUUID()}")
                if (!stage.mkdir() || Files.isSymbolicLink(stage.toPath()) || stage.canonicalFile.parentFile != root) {
                    throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
                }
                activeStages += stage.absolutePath
                stage
            }

        private fun isOrphanStage(stage: File): Boolean {
            if (!STAGE_NAME.matches(stage.name) || Files.isSymbolicLink(stage.toPath()) || !stage.isDirectory) {
                return false
            }
            return stage.absolutePath !in activeStages
        }

        private fun validatedParent(parent: File): File {
            // The caller supplies app-private storage; Android may alias its ancestor directories.
            // Reject a substituted parent leaf, then bind every stage to its canonical parent.
            if (Files.isSymbolicLink(parent.toPath())) {
                throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
            }
            val root = parent.canonicalFile
            if (!root.isDirectory) throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
            return root
        }

        private fun removeStage(stage: File) {
            if (Files.isSymbolicLink(stage.toPath())) {
                stage.delete()
                return
            }
            // Stages contain flat opaque files. Unexpected subdirectories are never traversed.
            stage.listFiles()?.forEach { child ->
                if (Files.isSymbolicLink(child.toPath()) || child.isFile) child.delete()
            }
            stage.delete()
        }

        val ORDER =
            compareBy<VaultFolder> { !it.isFolder }
                .thenBy(
                    String.CASE_INSENSITIVE_ORDER,
                ) { it.name }
                .thenBy { it.name }
                .thenBy { it.encryptedPath }
                .thenBy { it.id }

        val DESTINATION_ORDER = compareBy<VaultFolder> { it.name.lowercase() }
    }
}
