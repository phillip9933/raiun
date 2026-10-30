package eu.opencloud.android.next.core.security

import android.util.AtomicFile
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption

/** Atomic no-backup record IO and a process/cross-process fence shared by every store instance. */
internal class VaultDeviceRememberDisk(
    private val directory: File,
) {
    fun <T> withLock(block: () -> T): T =
        synchronized(LOCK) {
            ensureDirectory()
            val lockFile = File(directory, LOCK_FILE)
            requireSafeFile(lockFile)
            FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE).use { channel ->
                channel.lock().use { block() }
            }
        }

    fun readLedger(): RememberLedger {
        val file = File(directory, LEDGER_FILE)
        requireAtomicPaths(file)
        val atomic = AtomicFile(file)
        if (!file.exists() && !File(file.path + ".bak").exists()) return RememberLedger()
        val bytes = atomic.openRead().use { it.readBounded(MAX_LEDGER_BYTES) }
        return try {
            RememberLedger.decode(bytes)
        } finally {
            bytes.fill(0)
        }
    }

    fun writeLedger(ledger: RememberLedger) {
        val file = File(directory, LEDGER_FILE)
        requireAtomicPaths(file)
        val bytes = ledger.encode()
        var stream: FileOutputStream? = null
        val atomic = AtomicFile(file)
        try {
            check(bytes.size in 1..MAX_LEDGER_BYTES)
            stream = atomic.startWrite()
            stream.write(bytes)
            atomic.finishWrite(stream)
            stream = null
        } catch (error: IOException) {
            failWrite(atomic, stream, error)
        } catch (error: IllegalStateException) {
            failWrite(atomic, stream, error)
        } catch (error: IllegalArgumentException) {
            failWrite(atomic, stream, error)
        } catch (error: SecurityException) {
            failWrite(atomic, stream, error)
        } finally {
            bytes.fill(0)
        }
    }

    fun readRecord(identity: VaultIdentity): RememberRecord? = readRecordFile(recordFile(identity))

    fun readRecordAlias(identity: VaultIdentity): String? {
        val record = readRecord(identity) ?: return null
        return try {
            record.alias
        } finally {
            record.clear()
        }
    }

    fun readRecordIdentity(file: File): VaultIdentity? {
        val record = readRecordFile(file) ?: return null
        return try {
            record.identity
        } finally {
            record.clear()
        }
    }

    fun readRecordFile(file: File): RememberRecord? {
        requireAtomicPaths(file)
        if (!file.exists() && !File(file.path + ".bak").exists()) return null
        val bytes = AtomicFile(file).openRead().use { it.readBounded(MAX_RECORD_BYTES) }
        return try {
            RememberRecord.decode(bytes).also {
                val expectedAliasPrefix = "$ALIAS_PREFIX${it.identity.hashForRemember()}_"
                check(file.name == recordName(it.identity) && it.alias.startsWith(expectedAliasPrefix))
            }
        } finally {
            bytes.fill(0)
        }
    }

    fun writeRecord(
        identity: VaultIdentity,
        record: RememberRecord,
    ) {
        val file = recordFile(identity)
        requireAtomicPaths(file)
        val bytes = record.encode()
        var stream: FileOutputStream? = null
        val atomic = AtomicFile(file)
        try {
            stream = atomic.startWrite()
            stream.write(bytes)
            atomic.finishWrite(stream)
            stream = null
        } catch (error: IOException) {
            failWrite(atomic, stream, error)
        } catch (error: IllegalStateException) {
            failWrite(atomic, stream, error)
        } catch (error: IllegalArgumentException) {
            failWrite(atomic, stream, error)
        } catch (error: SecurityException) {
            failWrite(atomic, stream, error)
        } finally {
            bytes.fill(0)
        }
    }

    fun deleteRecord(identity: VaultIdentity) {
        val file = recordFile(identity)
        deleteAtomic(file)
    }

    fun listRecordFiles(): List<File> =
        directory
            .listFiles()
            ?.filter {
                it.name.startsWith(RECORD_PREFIX) &&
                    (
                        it.name.endsWith(RECORD_SUFFIX) ||
                            it.name.endsWith("$RECORD_SUFFIX.bak") ||
                            it.name.endsWith("$RECORD_SUFFIX.new")
                    )
            }?.map {
                when {
                    it.name.endsWith(".bak") -> File(directory, it.name.removeSuffix(".bak"))
                    it.name.endsWith(".new") -> File(directory, it.name.removeSuffix(".new"))
                    else -> it
                }
            }?.distinctBy(File::getName)
            ?.also { it.forEach(::requireAtomicPaths) }
            ?: emptyList()

    fun deletePartialRecordFile(file: File) {
        requireAtomicPaths(file)
        deleteAtomic(file)
    }

    private fun recordFile(identity: VaultIdentity) = File(directory, recordName(identity))

    private fun recordName(identity: VaultIdentity) = "$RECORD_PREFIX${identity.hashForRemember()}$RECORD_SUFFIX"

    private fun deleteAtomic(file: File) {
        requireAtomicPaths(file)
        AtomicFile(file).delete()
        check(!file.exists() && !File(file.path + ".bak").exists() && !File(file.path + ".new").exists()) {
            "Device remember record cleanup is incomplete."
        }
    }

    private fun failWrite(
        atomic: AtomicFile,
        stream: FileOutputStream?,
        error: IOException,
    ): Nothing {
        stream?.let(atomic::failWrite)
        throw error
    }

    private fun failWrite(
        atomic: AtomicFile,
        stream: FileOutputStream?,
        error: IllegalStateException,
    ): Nothing {
        stream?.let(atomic::failWrite)
        throw error
    }

    private fun failWrite(
        atomic: AtomicFile,
        stream: FileOutputStream?,
        error: IllegalArgumentException,
    ): Nothing {
        stream?.let(atomic::failWrite)
        throw error
    }

    private fun failWrite(
        atomic: AtomicFile,
        stream: FileOutputStream?,
        error: SecurityException,
    ): Nothing {
        stream?.let(atomic::failWrite)
        throw error
    }

    private fun ensureDirectory() {
        require(!Files.isSymbolicLink(directory.toPath()))
        if (!directory.exists()) check(directory.mkdirs())
        val canonicalDirectory = directory.canonicalFile
        val canonicalParent = directory.absoluteFile.parentFile?.canonicalFile
        check(
            directory.isDirectory &&
                canonicalParent != null &&
                canonicalDirectory.parentFile == canonicalParent &&
                canonicalDirectory.name == directory.name,
        )
    }

    private fun requireSafeFile(file: File) {
        require(!Files.isSymbolicLink(file.toPath()))
        check(file.canonicalFile.parentFile == directory.canonicalFile)
    }

    private fun requireAtomicPaths(file: File) {
        requireSafeFile(file)
        requireSafeFile(File(file.path + ".bak"))
        requireSafeFile(File(file.path + ".new"))
    }

    private fun InputStream.readBounded(limit: Int): ByteArray {
        val output = java.io.ByteArrayOutputStream(minOf(limit, 4096))
        val buffer = ByteArray(4096)
        try {
            var total = 0
            while (true) {
                val count = read(buffer)
                if (count < 0) break
                total += count
                require(total <= limit)
                output.write(buffer, 0, count)
            }
            require(total > 0)
            return output.toByteArray()
        } finally {
            buffer.fill(0)
        }
    }

    companion object {
        private const val LEDGER_FILE = "revocations.dat"
        private const val LOCK_FILE = ".store-lock"
        private const val RECORD_PREFIX = "remember_"
        private const val RECORD_SUFFIX = ".record"
        private const val ALIAS_PREFIX = "raiun_vault_device_v1_"
        private const val MAX_LEDGER_BYTES = 4 * 1024 * 1024
        private const val MAX_RECORD_BYTES = 128 * 1024
        private val LOCK = Any()
    }
}
