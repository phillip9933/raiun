package eu.opencloud.android.next.core.database

import java.io.Closeable
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** Owner proof and an OS lease are established before any resource metadata is written to this stage. */
internal class TemporaryCopyStage private constructor(
    val file: File,
    private val ownerFile: File,
    private val owner: FileChannel,
    private val lease: FileLock,
) : Closeable {
    private val closed = AtomicBoolean()

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        var removed = false
        try {
            deleteStageFiles(file)
            removed = true
        } finally {
            try {
                lease.release()
            } finally {
                owner.close()
                // Retain valid owner proof if deletion failed so a later stale pass can retry safely.
                if (removed) Files.deleteIfExists(ownerFile.toPath())
            }
        }
    }

    companion object {
        // Cleanup-only catch: release files/lease and rethrow even errors during private stage initialization.
        @Suppress("TooGenericExceptionCaught")
        fun create(directory: File): TemporaryCopyStage {
            if ((!directory.isDirectory && !directory.mkdirs()) || Files.isSymbolicLink(directory.toPath())) {
                throw IOException("Temporary-copy staging is unavailable.")
            }
            val parent = directory.canonicalFile
            cleanupStaleTemporaryCopyStages(parent)
            val file = File(parent, "ordinary-inventory-${UUID.randomUUID()}.sqlite")
            val ownerFile = File(file.path + ".owner")
            val owner =
                FileChannel.open(
                    ownerFile.toPath(),
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.READ,
                    StandardOpenOption.WRITE,
                    LinkOption.NOFOLLOW_LINKS,
                )
            var lease: FileLock? = null
            var created = false
            try {
                val marker = ByteBuffer.wrap(TEMPORARY_COPY_OWNER_MARKER.toByteArray(Charsets.UTF_8))
                while (marker.hasRemaining()) owner.write(marker)
                owner.force(true)
                lease = owner.lock()
                Files.createFile(file.toPath())
                created = true
                return TemporaryCopyStage(file, ownerFile, owner, lease)
            } catch (failure: Throwable) {
                try {
                    if (created) deleteStageFiles(file)
                } finally {
                    try {
                        lease?.release()
                    } finally {
                        owner.close()
                        Files.deleteIfExists(ownerFile.toPath())
                    }
                }
                throw failure
            }
        }
    }
}

internal const val TEMPORARY_COPY_OWNER_MARKER = "raiun-ordinary-copy-inventory-v1\n"

/** Bounded best-effort reclamation; unknown names, missing proof, symlinks and live owners are retained. */
internal fun cleanupStaleTemporaryCopyStages(directory: File) {
    val cutoff = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1)
    Files.newDirectoryStream(directory.toPath(), "ordinary-inventory-*.sqlite").use { entries ->
        val iterator = entries.iterator()
        var inspected = 0
        while (inspected < TEMPORARY_COPY_PAGE_SIZE && iterator.hasNext()) {
            val file = iterator.next().toFile()
            inspected++
            reclaimKnownStage(file, cutoff)
        }
    }
}

private fun reclaimKnownStage(
    file: File,
    cutoff: Long,
) {
    if (!STAGE_NAME.matches(file.name)) return
    try {
        reclaimStage(file, cutoff)
    } catch (_: IOException) {
        // Optional reclamation cannot turn an inaccessible old stage into an unsafe deletion.
    }
}

private fun reclaimStage(
    file: File,
    cutoff: Long,
) {
    val ownerFile = File(file.path + ".owner")
    if (!stalePrivatePair(file, ownerFile, cutoff)) return
    FileChannel
        .open(
            ownerFile.toPath(),
            StandardOpenOption.READ,
            StandardOpenOption.WRITE,
            LinkOption.NOFOLLOW_LINKS,
        ).use { owner ->
            withInactiveOwner(owner) {
                if (validOwner(owner) && stalePrivatePair(file, ownerFile, cutoff)) {
                    deleteStageFiles(file)
                    Files.deleteIfExists(ownerFile.toPath())
                }
            }
        }
}

private fun stalePrivatePair(
    file: File,
    ownerFile: File,
    cutoff: Long,
): Boolean = listOf(file, ownerFile).all { isRegularPrivateFile(it) && it.lastModified() < cutoff }

private inline fun withInactiveOwner(
    owner: FileChannel,
    block: () -> Unit,
) {
    val lease =
        try {
            owner.tryLock()
        } catch (_: OverlappingFileLockException) {
            null
        } ?: return
    lease.use { block() }
}

private fun validOwner(owner: FileChannel): Boolean {
    val expected = TEMPORARY_COPY_OWNER_MARKER.toByteArray(Charsets.UTF_8)
    return owner.size() == expected.size.toLong() && readOwnerMarker(owner, expected)
}

private fun readOwnerMarker(
    owner: FileChannel,
    expected: ByteArray,
): Boolean {
    val marker = ByteBuffer.allocate(expected.size)
    owner.position(0)
    while (marker.hasRemaining()) {
        if (owner.read(marker) <= 0) return false
    }
    return marker.array().contentEquals(expected)
}

private fun isRegularPrivateFile(file: File): Boolean =
    Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(file.toPath())

private fun deleteStageFiles(file: File) {
    val files = listOf(File(file.path + "-journal"), File(file.path + "-wal"), File(file.path + "-shm"), file)
    if (files.any { Files.exists(it.toPath(), LinkOption.NOFOLLOW_LINKS) && !isRegularPrivateFile(it) }) {
        throw IOException("Temporary-copy staging ownership changed.")
    }
    files.forEach { Files.deleteIfExists(it.toPath()) }
}

private val STAGE_NAME =
    Regex("ordinary-inventory-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.sqlite")
