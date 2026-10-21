package eu.opencloud.android.next.core.sync

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import java.io.Closeable
import java.io.File
import java.io.RandomAccessFile
import java.nio.channels.OverlappingFileLockException
import java.nio.file.Files
import java.util.concurrent.TimeUnit

/** A separate advisory lock protects active traversals from stale-file maintenance.
 * Constructor failures, including cancellation, must release private traversal files.
 */
@Suppress("TooGenericExceptionCaught")
internal class BackupTraversalFile(
    context: Context,
) : Closeable {
    val file: File
    private val ownerFile: File
    private val owner: RandomAccessFile
    private val lock: java.nio.channels.FileLock

    init {
        cleanupStaleTraversals(context.noBackupFilesDir)
        file = File.createTempFile("backup-traversal-", ".db", context.noBackupFilesDir)
        ownerFile = File(file.path + ".owner")
        owner =
            try {
                RandomAccessFile(ownerFile, "rw")
            } catch (failure: Throwable) {
                file.delete()
                throw failure
            }
        try {
            lock = owner.channel.lock()
        } catch (failure: Throwable) {
            owner.close()
            ownerFile.delete()
            file.delete()
            throw failure
        }
    }

    override fun close() {
        try {
            SQLiteDatabase.deleteDatabase(file)
        } finally {
            try {
                lock.release()
            } finally {
                owner.close()
                ownerFile.delete()
            }
        }
    }
}

private fun cleanupStaleTraversals(directory: File) {
    val cutoff = System.currentTimeMillis() - TimeUnit.DAYS.toMillis(1)
    Files.newDirectoryStream(directory.toPath(), "backup-traversal-*.db").use { files ->
        files.take(128).forEach { path ->
            val file = path.toFile()
            if (file.lastModified() < cutoff) deleteInactiveTraversal(file)
        }
    }
}

private fun deleteInactiveTraversal(file: File) {
    val ownerFile = File(file.path + ".owner")
    RandomAccessFile(ownerFile, "rw").use { owner ->
        val lock =
            try {
                owner.channel.tryLock()
            } catch (_: OverlappingFileLockException) {
                null
            }
        if (lock != null) {
            lock.use { SQLiteDatabase.deleteDatabase(file) }
            ownerFile.delete()
        }
    }
}
