package eu.opencloud.android.next.core.sync

import android.content.Context
import java.io.File
import java.nio.file.Files
import java.util.UUID

/** Process-local, non-resumable storage for plaintext emitted by the scanner SDK. */
class VaultScanTempStore(
    context: Context,
) {
    private val root = File(context.applicationContext.noBackupFilesDir, ROOT_NAME)

    init {
        initializeProcess(context.applicationContext)
    }

    fun createSession(): VaultScanTempSession {
        synchronized(processLock) {
            check(prepared) { "Encrypted scanner storage has not been prepared." }
            check(!Files.isSymbolicLink(root.toPath()) && root.isDirectory) {
                "Encrypted scanner temporary storage is unavailable."
            }
            root.listFiles().orEmpty().filter { it.name !in activeSessions }.forEach { stale ->
                check(deleteTreeWithoutFollowingLinks(stale)) { "Could not remove interrupted scanner output." }
            }
            val directory = File(root, UUID.randomUUID().toString())
            check(directory.mkdirs()) { "Could not create encrypted scanner temporary storage." }
            check(!Files.isSymbolicLink(directory.toPath()) && directory.isDirectory) {
                "Could not create encrypted scanner temporary storage."
            }
            activeSessions += directory.name
            return VaultScanTempSession(directory)
        }
    }

    internal companion object {
        private const val ROOT_NAME = "vault-scan-temp"
        private val processLock = Any()
        private val activeSessions = mutableSetOf<String>()
        private var prepared = false

        /** Removes scan plaintext left by an interrupted process; call from application startup. */
        fun initializeProcess(context: Context) {
            synchronized(processLock) {
                val directory = File(context.applicationContext.noBackupFilesDir, ROOT_NAME)
                prepareForProcess(directory)
            }
        }

        private fun prepareForProcess(directory: File) {
            if (prepared) return
            if (directory.exists() || Files.isSymbolicLink(directory.toPath())) {
                check(deleteTreeWithoutFollowingLinks(directory)) { "Could not remove interrupted scanner output." }
            }
            check(directory.mkdirs() || directory.isDirectory) { "Could not prepare encrypted scanner storage." }
            prepared = true
        }

        fun unregister(sessionId: String) {
            synchronized(processLock) { activeSessions.remove(sessionId) }
        }

        private fun deleteTreeWithoutFollowingLinks(file: File): Boolean {
            if (Files.isSymbolicLink(file.toPath())) return file.delete()
            val children = if (file.isDirectory) file.listFiles() else emptyArray()
            return children?.all(::deleteTreeWithoutFollowingLinks) == true && file.delete()
        }

        fun removeTree(file: File): Boolean = deleteTreeWithoutFollowingLinks(file)
    }
}

/** A single live scanner run. Nothing about this session is serialized or recoverable. */
class VaultScanTempSession internal constructor(
    private val directory: File,
) {
    val outputDirectory: File
        get() {
            check(directory.isDirectory) { "The encrypted scanner session is closed." }
            return directory
        }

    fun validatedFiles(files: List<File>): List<File> {
        check(directory.isDirectory) { "The encrypted scanner session is closed." }
        require(files.isNotEmpty()) { "The scanner did not create any files." }
        val base = directory.canonicalFile.toPath()
        return files.map { file ->
            val path = file.canonicalFile.toPath()
            require(
                !hasSymlinkInPath(file) &&
                    path.startsWith(base) &&
                    path != base &&
                    file.isFile &&
                    file.length() > 0L &&
                    file.name.isNotBlank() &&
                    file.name.none { it == '/' || it == '\\' || it.isISOControl() },
            ) { "Scanner output must stay in its temporary session." }
            file.canonicalFile
        }
    }

    /** Removes all scanner output, including incomplete SDK output. Flash translation may retain old blocks. */
    fun discard() {
        if (!directory.exists() && !Files.isSymbolicLink(directory.toPath())) return
        val deleted = VaultScanTempStore.removeTree(directory)
        VaultScanTempStore.unregister(directory.name)
        check(deleted && !directory.exists()) { "Could not remove encrypted scanner temporary output." }
    }

    private fun hasSymlinkInPath(file: File): Boolean {
        var current: File? = file.absoluteFile
        while (current != null && current.toPath().startsWith(directory.absoluteFile.toPath())) {
            if (Files.isSymbolicLink(current.toPath())) return true
            if (current == directory.absoluteFile) break
            current = current.parentFile
        }
        return false
    }
}
