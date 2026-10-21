package eu.opencloud.android.next.core.sync

import android.content.Context
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Contains ciphertext and public server identity only. Never stores plaintext names or vault keys. */
internal data class VaultUploadJob(
    val id: String,
    val location: VaultLocation,
    val destination: String,
    val expectedETag: String?,
    val rootProofDigest: String,
    val size: Long,
    val digest: String,
)

/** Private, no-backup durable payloads. A complete manifest is the commit marker for a job. */
internal class VaultUploadStore(
    private val root: File,
) {
    constructor(context: Context) : this(File(context.noBackupFilesDir, "vault-upload-jobs"))

    @Suppress("TooGenericExceptionCaught")
    fun prepare(
        location: VaultLocation,
        destination: String,
        expectedETag: String?,
        rootProofDigest: String,
        writeCiphertext: (OutputStream) -> Unit,
    ): VaultUploadJob {
        vaultJobRequireWrite(root.mkdirs() || root.isDirectory)
        check(
            !java.nio.file.Files
                .isSymbolicLink(root.toPath()),
        )
        val id = UUID.randomUUID().toString()
        val directory = File(root, id)
        synchronized(lock) {
            vaultJobRequireWrite(directory.mkdir())
            active.add(id)
            preparedAccounts[id] = location.accountId to accountRevisions.getOrDefault(location.accountId, 0L)
        }
        try {
            val payload = File(directory, "content")
            val contentDigest = MessageDigest.getInstance("SHA-256")
            vaultJobWrite { FileOutputStream(payload) }.use { output ->
                val bounded =
                    object : java.io.FilterOutputStream(output) {
                        override fun write(value: Int) {
                            write(byteArrayOf(value.toByte()), 0, 1)
                        }

                        override fun write(
                            buffer: ByteArray,
                            offset: Int,
                            length: Int,
                        ) {
                            if (root.usableSpace < length.toLong() + 16L * 1024 * 1024) {
                                throw eu.opencloud.android.next.core.network.OpenCloudException(
                                    eu.opencloud.android.next.core.network.OpenCloudError.LocalStorage,
                                )
                            }
                            vaultJobWrite { out.write(buffer, offset, length) }
                            contentDigest.update(buffer, offset, length)
                        }
                    }
                writeCiphertext(bounded)
                vaultJobWrite { output.fd.sync() }
            }
            val job =
                VaultUploadJob(
                    id,
                    location.copy(title = ""),
                    destination,
                    expectedETag,
                    rootProofDigest,
                    payload.length(),
                    contentDigest.digest().joinToString("") { byte -> "%02x".format(byte) },
                )
            validate(job)
            vaultJobWrite {
                FileOutputStream(File(directory, "manifest.tmp")).use { output ->
                    DataOutputStream(output).apply {
                        writeInt(1)
                        writeUTF(job.id)
                        writeUTF(location.accountId)
                        writeUTF(location.kind.name)
                        writeUTF(location.driveId)
                        writeUTF(location.remoteVaultId)
                        writeUTF(location.sourceRootId)
                        writeUTF(location.canonicalServer)
                        writeUTF(location.rootWebDavUrl)
                        writeUTF(location.vaultPath)
                        writeUTF(destination)
                        writeBoolean(expectedETag != null)
                        expectedETag?.let(::writeUTF)
                        writeUTF(rootProofDigest)
                        writeLong(job.size)
                        writeUTF(job.digest)
                        flush()
                    }
                    vaultJobWrite { output.fd.sync() }
                }
            }
            vaultJobRequireWrite(File(directory, "manifest.tmp").renameTo(File(directory, "manifest")))
            return job
        } catch (error: Exception) {
            deleteVaultJobTree(directory)
            active.remove(id)
            preparedAccounts.remove(id)
            throw error
        }
    }

    private fun readManifest(id: String): VaultUploadJob =
        synchronized(lock) {
            val directory = directory(id)
            check(
                !java.nio.file.Files
                    .isSymbolicLink(directory.toPath()),
            )
            val manifest = File(directory, "manifest")
            check(
                manifest.length() in 1..32_768 &&
                    !java.nio.file.Files
                        .isSymbolicLink(manifest.toPath()),
            )
            val job =
                DataInputStream(FileInputStream(manifest)).use { input ->
                    check(input.readInt() == 1)
                    val storedId = input.readUTF()
                    val location =
                        VaultLocation(
                            accountId = input.readUTF(),
                            title = "",
                            kind = VaultLocationKind.valueOf(input.readUTF()),
                            driveId = input.readUTF(),
                            remoteVaultId = input.readUTF(),
                            sourceRootId = input.readUTF(),
                            canonicalServer = input.readUTF(),
                            rootWebDavUrl = input.readUTF(),
                            vaultPath = input.readUTF(),
                            isVaultRoot = true,
                        )
                    VaultUploadJob(
                        storedId,
                        location,
                        input.readUTF(),
                        if (input.readBoolean()) input.readUTF() else null,
                        input.readUTF(),
                        input.readLong(),
                        input.readUTF(),
                    ).also { check(input.read() == -1 && it.id == id) }
                }
            validate(job)
            val payload = File(directory, "content")
            check(
                !java.nio.file.Files
                    .isSymbolicLink(payload.toPath()) &&
                    payload.length() == job.size,
            )
            job
        }

    fun finishPrepared(
        id: String,
        retain: () -> Boolean,
    ): Boolean =
        synchronized(lock) {
            val binding = preparedAccounts.remove(id)
            active.remove(id)
            val revoked = binding != null && accountRevisions.getOrDefault(binding.first, 0L) != binding.second
            val keep = !revoked && retain()
            if (!keep) check(deleteVaultJobTree(directory(id)))
            keep
        }

    fun ids(): List<String> = synchronized(lock) { root.listFiles().orEmpty().map { it.name } }

    fun read(
        id: String,
        checkActive: () -> Unit = {},
    ): VaultUploadJob =
        vaultJobRead {
            val job = readManifest(id)
            val input =
                object : java.io.FilterInputStream(open(job)) {
                    override fun read(
                        buffer: ByteArray,
                        offset: Int,
                        length: Int,
                    ): Int {
                        checkActive()
                        return `in`.read(buffer, offset, length)
                    }
                }
            check(vaultUploadDigest(input) == job.digest)
            job
        }

    fun open(job: VaultUploadJob): InputStream = vaultJobRead { FileInputStream(File(directory(job.id), "content")) }

    fun delete(id: String) =
        synchronized(lock) {
            check(deleteVaultJobTree(directory(id)))
            active.remove(id)
            preparedAccounts.remove(id)
        }

    /** Orphan payloads include interrupted encryption and the manifest-before-Room commit gap. */
    fun reconcile(isRetained: (String) -> Boolean) =
        synchronized(lock) {
            root.listFiles().orEmpty().filter { it.name !in active && !isRetained(it.name) }.forEach {
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(it.toPath()),
                )
                check(deleteVaultJobTree(it))
            }
        }

    fun forgetAccount(accountId: String) =
        synchronized(lock) {
            accountRevisions[accountId] = accountRevisions.getOrDefault(accountId, 0L) + 1
            root.listFiles().orEmpty().filter { it.name !in active }.forEach { directory ->
                val job = runCatching { readManifest(directory.name) }.getOrNull()
                if (job == null || job.location.accountId == accountId) check(deleteVaultJobTree(directory))
            }
        }

    private fun directory(id: String): File {
        require(UUID.fromString(id).toString() == id)
        return File(root, id)
    }

    private fun validate(job: VaultUploadJob) {
        require(UUID.fromString(job.id).toString() == job.id)
        require(job.location.kind in setOf(VaultLocationKind.FOLDER_VAULT, VaultLocationKind.SPACE_VAULT))
        require(job.location.accountId.isNotBlank() && job.location.remoteVaultId.isNotBlank())
        val rootPath = job.location.vaultPath.trim('/')
        require(job.destination.isNotBlank() && (rootPath.isEmpty() || job.destination.startsWith("$rootPath/")))
        require(
            job.destination.split('/').none {
                it.isEmpty() ||
                    it == "." ||
                    it == ".." ||
                    '\\' in it ||
                    it.any(Char::isISOControl)
            },
        )
        require(job.size >= 32 && job.digest.matches(Regex("[a-f0-9]{64}")))
        require(job.rootProofDigest.matches(Regex("[a-f0-9]{64}")))
        job.expectedETag?.let { require(it.startsWith('"') && it.endsWith('"') && !it.any(Char::isISOControl)) }
    }

    companion object {
        private val lock = Any()
        private val active = ConcurrentHashMap.newKeySet<String>()
        private val preparedAccounts = ConcurrentHashMap<String, Pair<String, Long>>()
        private val accountRevisions = ConcurrentHashMap<String, Long>()
    }
}

internal fun vaultUploadDigest(input: InputStream): String =
    input.use {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val size = it.read(buffer)
            if (size < 0) break
            digest.update(buffer, 0, size)
        }
        digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

internal fun vaultProofDigest(token: String): String = vaultUploadDigest(token.byteInputStream(Charsets.UTF_8))
