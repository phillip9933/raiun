package eu.opencloud.android.next.core.sync

import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.nio.file.Files

/** Only owned directory entries up to the configured private boundary are synchronized. */
internal class OfflineDurability(
    private val boundary: File,
    private val syncDirectory: (File) -> Unit = ::fsyncOfflineDirectory,
) {
    fun syncParents(directory: File) {
        var current = requireOwnedDirectory(directory)
        val end = boundary.canonicalFile
        while (true) {
            if (!current.isDirectory || Files.isSymbolicLink(current.toPath())) {
                throw IOException("Offline metadata directory is unavailable")
            }
            syncDirectory(current)
            if (current == end) break
            current = current.parentFile ?: throw IOException("Offline metadata boundary is unavailable")
        }
    }

    @Suppress("TooGenericExceptionCaught") // AtomicFile must roll back every incomplete byte write.
    fun writeAtomic(
        file: File,
        bytes: ByteArray,
    ) {
        val parent = requireOwnedDirectory(requireNotNull(file.parentFile))
        requireRegularMetadataPath(file)
        if (!parent.mkdirs() && !parent.isDirectory) throw IOException("Offline metadata directory is unavailable")
        val atomic = AtomicFile(file)
        val output = atomic.startWrite()
        try {
            output.write(bytes)
            atomic.finishWrite(output)
        } catch (failure: Exception) {
            atomic.failWrite(output)
            throw failure
        }
        // A directory-sync failure is handled by the publication journal, not by AtomicFile's byte rollback.
        syncParents(parent)
    }

    fun deleteAtomic(file: File) {
        val parent = requireOwnedDirectory(requireNotNull(file.parentFile))
        requireRegularMetadataPath(file)
        AtomicFile(file).delete()
        if (file.exists() || File(file.path + ".bak").exists()) throw IOException("Offline metadata removal failed")
        syncParents(parent)
    }

    /** Pure preflight, with no IO mutation. Platform aliases above the private boundary are valid. */
    fun requireOwnedDirectory(directory: File): File {
        val current = directory.canonicalFile
        val canonicalBoundary = boundary.canonicalFile.toPath()
        requireConfinement(
            current.toPath().startsWith(canonicalBoundary),
            "Offline metadata is outside its private boundary",
        )
        val rawBoundary = boundary.absoluteFile.toPath().normalize()
        requireConfinement(!Files.isSymbolicLink(rawBoundary), "Offline metadata boundary is redirected")
        var raw = directory.absoluteFile.toPath().normalize()
        val validationBoundary =
            when {
                raw.startsWith(rawBoundary) -> rawBoundary
                raw.startsWith(canonicalBoundary) -> canonicalBoundary
                else -> throw IOException("Offline metadata is outside its private boundary")
            }
        while (true) {
            requireConfinement(!Files.isSymbolicLink(raw), "Offline metadata directory is redirected")
            if (raw == validationBoundary) break
            raw = raw.parent ?: throw IOException("Offline metadata boundary is unavailable")
        }
        return current
    }

    private fun requireConfinement(
        condition: Boolean,
        message: String,
    ) {
        if (!condition) throw IOException(message)
    }

    private fun requireRegularMetadataPath(file: File) {
        listOf(file, File(file.path + ".bak"), File(file.path + ".new")).forEach {
            if (Files.isSymbolicLink(it.toPath())) throw IOException("Offline metadata file is redirected")
        }
    }
}

/** Successful native return proves syscall invocation, not a Room/filesystem power-loss transaction. */
internal fun fsyncOfflineDirectory(directory: File) {
    try {
        val flags = OsConstants.O_RDONLY or OsConstants.O_NOFOLLOW or OsConstants.O_CLOEXEC
        val descriptor = Os.open(directory.path, flags, 0)
        try {
            if (!OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode)) {
                throw IOException("Offline sync target is not a directory")
            }
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    } catch (failure: ErrnoException) {
        throw IOException("Offline directory synchronization failed", failure)
    }
}

internal fun readOfflineMetadata(
    file: File,
    maximum: Int,
    durability: OfflineDurability = OfflineDurability(requireNotNull(file.parentFile)),
): ByteArray {
    val restoringBackup = File(file.path + ".bak").exists()
    val bytes = AtomicFile(file).openRead().use { readBoundedMetadata(it, maximum) }
    if (restoringBackup) durability.syncParents(requireNotNull(file.parentFile))
    return bytes
}

private fun readBoundedMetadata(
    input: java.io.InputStream,
    maximum: Int,
): ByteArray {
    val output = ByteArrayOutputStream(minOf(maximum, 64 * 1024))
    val buffer = ByteArray(64 * 1024)
    try {
        while (true) {
            val count = input.read(buffer, 0, minOf(buffer.size, maximum - output.size() + 1))
            if (count < 0) break
            output.write(buffer, 0, count)
            if (output.size() > maximum) throw OpenCloudException(OpenCloudError.InvalidResponse)
        }
        return output.toByteArray()
    } finally {
        buffer.fill(0)
    }
}
