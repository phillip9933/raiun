package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.VaultDavEntry
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

internal data class VaultDownloadJob(
    val id: String,
    val location: VaultLocation,
    val source: VaultDavEntry,
    val rootProofDigest: String?,
)

/** Only encrypted paths and original ciphertext. Downloaded bytes remain untrusted until unlock. */
internal class VaultDownloadStore(
    private val root: File,
) {
    constructor(context: Context) : this(File(context.noBackupFilesDir, "vault-download-jobs"))

    @Suppress("TooGenericExceptionCaught")
    fun create(
        location: VaultLocation,
        source: VaultDavEntry,
        rootProofDigest: String?,
    ): VaultDownloadJob {
        val job = VaultDownloadJob(UUID.randomUUID().toString(), location.copy(title = ""), source, rootProofDigest)
        validate(job)
        val directory =
            synchronized(lock) {
                vaultJobRequireWrite(root.mkdirs() || root.isDirectory)
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(root.toPath()),
                )
                File(root, job.id).also {
                    vaultJobRequireWrite(it.mkdir())
                    prepared.add(job.id)
                    preparedAccounts[job.id] =
                        location.accountId to accountRevisions.getOrDefault(location.accountId, 0L)
                }
            }
        try {
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
                        writeUTF(source.id)
                        writeUTF(source.relativePath)
                        writeUTF(source.rawName)
                        writeLong(source.size)
                        writeBoolean(source.strongETag != null)
                        source.strongETag?.let(::writeUTF)
                        writeUTF(source.href)
                        writeBoolean(rootProofDigest != null)
                        rootProofDigest?.let(::writeUTF)
                        flush()
                    }
                    vaultJobWrite { output.fd.sync() }
                }
            }
            vaultJobRequireWrite(File(directory, "manifest.tmp").renameTo(File(directory, "manifest")))
            return job
        } catch (error: Exception) {
            delete(job.id)
            throw error
        }
    }

    fun read(id: String): VaultDownloadJob =
        vaultJobRead {
            synchronized(lock) {
                val directory = directory(id)
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(directory.toPath()),
                )
                val manifest = File(directory, "manifest")
                check(
                    !java.nio.file.Files
                        .isSymbolicLink(manifest.toPath()) &&
                        manifest.length() in 1..32_768,
                )
                DataInputStream(FileInputStream(manifest)).use { input ->
                    check(input.readInt() == 1)
                    val storedId = input.readUTF()
                    val location =
                        VaultLocation(
                            input.readUTF(),
                            "",
                            VaultLocationKind.valueOf(input.readUTF()),
                            input.readUTF(),
                            input.readUTF(),
                            input.readUTF(),
                            input.readUTF(),
                            input.readUTF(),
                            input.readUTF(),
                            true,
                        )
                    val sourceId = input.readUTF()
                    val path = input.readUTF()
                    val name = input.readUTF()
                    val size = input.readLong()
                    val etag = if (input.readBoolean()) input.readUTF() else null
                    val source = VaultDavEntry(sourceId, path, name, false, size, etag, input.readUTF())
                    val proof = if (input.readBoolean()) input.readUTF() else null
                    VaultDownloadJob(storedId, location, source, proof).also {
                        check(storedId == id && input.read() == -1)
                        validate(it)
                    }
                }
            }
        }

    fun finishPrepared(
        id: String,
        retain: () -> Boolean,
    ): Boolean =
        synchronized(lock) {
            val binding = preparedAccounts.remove(id)
            prepared.remove(id)
            val revoked = binding != null && accountRevisions.getOrDefault(binding.first, 0L) != binding.second
            val keep = !revoked && retain()
            if (!keep) check(deleteVaultJobTree(directory(id)))
            keep
        }

    fun discardPayload(id: String) =
        synchronized(lock) {
            attempts[id]?.forEach { it.cancel() }
            val directory = directory(id)
            listOf("content", "checkpoint").forEach { check(deleteVaultJobTree(File(directory, it))) }
        }

    fun ids(): List<String> = synchronized(lock) { root.listFiles().orEmpty().map { it.name } }

    fun partial(job: VaultDownloadJob): File = localFile(job.id, "content")

    fun checkpoint(job: VaultDownloadJob): File = localFile(job.id, "checkpoint")

    fun delete(id: String) =
        synchronized(lock) {
            attempts[id]?.forEach { it.cancel() }
            check(deleteVaultJobTree(directory(id)))
            prepared.remove(id)
            preparedAccounts.remove(id)
        }

    fun reconcile(isRetained: (String) -> Boolean) =
        synchronized(lock) {
            root.listFiles().orEmpty().filter { it.name !in prepared && !isRetained(it.name) }.forEach {
                attempts[it.name]?.forEach { attempt -> attempt.cancel() }
                check(deleteVaultJobTree(it))
            }
        }

    fun forgetAccount(accountId: String) =
        synchronized(lock) {
            accountRevisions[accountId] = accountRevisions.getOrDefault(accountId, 0L) + 1
            attempts.values
                .flatten()
                .filter { it.accountId == accountId }
                .forEach { it.cancel() }
            root.listFiles().orEmpty().filter { it.name !in prepared }.forEach {
                val job = runCatching { read(it.name) }.getOrNull()
                if (job == null || job.location.accountId == accountId) check(deleteVaultJobTree(it))
            }
        }

    private fun localFile(
        id: String,
        name: String,
    ): File {
        val directory = directory(id)
        check(
            directory.isDirectory &&
                !java.nio.file.Files
                    .isSymbolicLink(directory.toPath()),
        )
        return File(directory, name).also {
            check(
                !java.nio.file.Files
                    .isSymbolicLink(it.toPath()),
            )
        }
    }

    private fun directory(id: String): File {
        require(UUID.fromString(id).toString() == id)
        return File(root, id)
    }

    private fun validate(job: VaultDownloadJob) {
        require(UUID.fromString(job.id).toString() == job.id)
        require(job.location.kind in setOf(VaultLocationKind.FOLDER_VAULT, VaultLocationKind.SPACE_VAULT))
        require(job.location.accountId.isNotBlank() && job.location.remoteVaultId.isNotBlank())
        require(job.source.id.isNotBlank() && !job.source.isFolder && job.source.size >= 32)
        val rootPath = job.location.vaultPath.trim('/')
        require(rootPath.isEmpty() || job.source.relativePath.startsWith("$rootPath/"))
        require(
            job.source.relativePath.split('/').none {
                it.isBlank() ||
                    it == "." ||
                    it == ".." ||
                    '\\' in it ||
                    it.any(Char::isISOControl)
            },
        )
        require(job.source.rawName == job.source.relativePath.substringAfterLast('/'))
        require(job.rootProofDigest == null || job.rootProofDigest.matches(Regex("[a-f0-9]{64}")))
        job.source.strongETag?.let {
            require(
                eu.opencloud.android.next.core.network
                    .DownloadExpectation(job.source.size, it)
                    .strongETag == it,
            )
        }
    }

    /** Cancellation belongs to live attempts; Room is the durable authority for subsequent attempts. */
    fun beginAttempt(
        id: String,
        accountId: String,
    ): Attempt =
        synchronized(lock) {
            Attempt(id, accountId).also { attempts.getOrPut(id) { mutableSetOf() }.add(it) }
        }

    internal class Attempt(
        private val id: String,
        val accountId: String,
    ) : AutoCloseable {
        private val active = AtomicBoolean(true)
        val isActive: Boolean get() = active.get()

        fun cancel() {
            active.set(false)
        }

        override fun close() =
            synchronized(lock) {
                active.set(false)
                attempts[id]?.let { registered ->
                    registered.remove(this)
                    if (registered.isEmpty()) attempts.remove(id)
                }
                Unit
            }
    }

    companion object {
        private val lock = Any()
        private val prepared = ConcurrentHashMap.newKeySet<String>()
        private val preparedAccounts = ConcurrentHashMap<String, Pair<String, Long>>()
        private val accountRevisions = ConcurrentHashMap<String, Long>()
        val publishing = ConcurrentHashMap.newKeySet<String>()
        private val attempts = mutableMapOf<String, MutableSet<Attempt>>()

        internal fun activeAttemptCount(): Int = synchronized(lock) { attempts.values.sumOf { it.size } }
    }
}

internal fun VaultDownloadJob.matchesLocation(current: VaultLocation): Boolean =
    location.accountId == current.accountId &&
        location.canonicalServer == current.canonicalServer &&
        location.driveId == current.driveId &&
        location.remoteVaultId == current.remoteVaultId &&
        location.sourceRootId == current.sourceRootId &&
        location.kind == current.kind &&
        location.rootWebDavUrl == current.rootWebDavUrl &&
        location.vaultPath == current.vaultPath

internal fun VaultDownloadJob.decryptedOfflineEntry(cipher: VaultCipherEngine): VaultFolder {
    val relative =
        if (location.vaultPath.isEmpty()) {
            source.relativePath
        } else {
            source.relativePath.removePrefix("${location.vaultPath}/")
        }
    val path = cipher.decryptPath(relative)
    if (path.split('/').any { invalidOfflineSegment(it) }) {
        throw eu.opencloud.android.next.core.network.OpenCloudException(
            eu.opencloud.android.next.core.network.OpenCloudError.DownloadIntegrity,
        )
    }
    return VaultFolder(
        source.id,
        path.substringAfterLast('/'),
        source.rawName,
        path,
        source.relativePath,
        false,
        source.size,
        source.strongETag,
    )
}

private fun invalidOfflineSegment(segment: String): Boolean {
    val traversal = segment.isBlank() || segment in setOf(".", "..")
    val malformed = '\\' in segment || segment.any(Char::isISOControl)
    return traversal || malformed
}
