package eu.opencloud.android.next.core.sync

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.SystemClock
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit

/** Bounded process-local handoff of decrypted files to an explicitly selected external app. */
object VaultExternalCopyStore {
    const val LEASE_DURATION_MILLIS = 10 * 60 * 1000L
    private const val ROOT_NAME = "vault-external-copies"
    private const val DATA_FILE = "content"
    private const val CLEANUP_WORK_PREFIX = "vault-external-copy-"
    private val MIME_PATTERN = Regex("[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+")
    private val processLock = Any()
    private val entriesByRoot = ConcurrentHashMap<String, ConcurrentHashMap<String, Entry>>()
    private val unavailableRoots = ConcurrentHashMap.newKeySet<String>()
    internal var clockForTests: (() -> Long)? = null
    internal var cleanupFailureForTests: ((File) -> Boolean)? = null

    /** Writes one plaintext export privately; failed or cancelled writes remove their partial file. */
    suspend fun create(
        context: Context,
        name: String,
        mimeType: String,
        writer: suspend (OutputStream) -> Unit,
    ): VaultExternalCopyLease {
        var createdLease: VaultExternalCopyLease? = null
        return try {
            withContext(Dispatchers.IO) {
                val app = context.applicationContext
                val root = prepareRoot(app)
                val id = UUID.randomUUID().toString()
                val directory = File(root, id)
                check(directory.mkdir() && !Files.isSymbolicLink(directory.toPath())) {
                    "Could not create temporary export."
                }
                var published = false
                try {
                    val file = File(directory, DATA_FILE)
                    check(file.createNewFile()) { "Could not create temporary export." }
                    FileOutputStream(file).use { output -> writer(output) }
                    val metadata =
                        Entry(
                            uri =
                                Uri
                                    .Builder()
                                    .scheme("content")
                                    .authority("${app.packageName}.vault-export")
                                    .appendPath(id)
                                    .build(),
                            displayName = safeDisplayName(name),
                            mimeType = safeMimeType(mimeType),
                            expiresAtMillis = nowMillis() + LEASE_DURATION_MILLIS,
                            file = file,
                        )
                    entries(root).put(id, metadata)
                    val request =
                        OneTimeWorkRequestBuilder<VaultExternalCopyCleanupWorker>()
                            .setInitialDelay(LEASE_DURATION_MILLIS, TimeUnit.MILLISECONDS)
                            .setInputData(androidx.work.workDataOf(VaultExternalCopyCleanupWorker.KEY_ID to id))
                            .build()
                    WorkManager.getInstance(app).enqueueUniqueWork(
                        CLEANUP_WORK_PREFIX + id,
                        ExistingWorkPolicy.REPLACE,
                        request,
                    )
                    published = true
                    VaultExternalCopyLease(app, metadata.uri, id).also { createdLease = it }
                } finally {
                    if (!published) {
                        entries(root).remove(id)
                        if (!cleanupDirectory(directory)) scheduleCleanup(app, id)
                    }
                }
            }
        } catch (cancelled: CancellationException) {
            createdLease?.cleanup()
            throw cancelled
        }
    }

    /** Clears exports interrupted by process death. Unexpired leases are intentionally process-bound. */
    fun initializeProcess(
        context: Context,
        scheduleRetry: Boolean = true,
    ): Boolean {
        val app = context.applicationContext
        val root = File(app.noBackupFilesDir, ROOT_NAME)
        val rootPath = runCatching { root.canonicalPath }.getOrNull() ?: root.absolutePath
        return synchronized(processLock) {
            unavailableRoots += rootPath
            entriesByRoot.remove(rootPath)
            val ready =
                try {
                    val cleared = !root.exists() && !Files.isSymbolicLink(root.toPath()) || cleanupDirectory(root)
                    cleared && (root.mkdirs() || root.isDirectory) && !Files.isSymbolicLink(root.toPath())
                } catch (_: Exception) {
                    false
                }
            if (ready) {
                entriesByRoot[root.canonicalPath] = ConcurrentHashMap()
                unavailableRoots.remove(rootPath)
            } else if (scheduleRetry) {
                scheduleCleanup(app, ROOT_CLEANUP_ID_FOR_WORKER)
            }
            ready
        }
    }

    /** Resolves only a live process-local lease for this app's opaque provider URI. */
    fun find(
        context: Context,
        uri: Uri,
    ): VaultExternalCopyMetadata? = resolveEntry(context, uri)?.toPublicMetadata()

    /** Returns the private file only after verifying the URI and active lease registry. */
    fun openReadOnly(
        context: Context,
        uri: Uri,
    ): File? = resolveEntry(context, uri)?.file

    /** Revokes this URI and removes its file and process-local metadata. Safe to call repeatedly. */
    fun cleanup(
        context: Context,
        id: String,
    ): Boolean = cleanup(context, id, cancelWork = true)

    internal fun cleanupFromWorker(
        context: Context,
        id: String,
    ): Boolean = cleanup(context, id, cancelWork = false)

    internal fun cleanupStartupFromWorker(context: Context): Boolean {
        val app = context.applicationContext
        val root = File(app.noBackupFilesDir, ROOT_NAME)
        val rootPath = runCatching { root.canonicalPath }.getOrNull() ?: root.absolutePath
        synchronized(processLock) {
            if (rootPath !in unavailableRoots && root.absolutePath !in unavailableRoots) return true
            return initializeProcess(app, scheduleRetry = false)
        }
    }

    private fun cleanup(
        context: Context,
        id: String,
        cancelWork: Boolean,
    ): Boolean =
        id
            .takeIf(::isUuid)
            ?.let { runCatching { cleanupValidated(context.applicationContext, it, cancelWork) }.getOrDefault(false) }
            ?: false

    private fun cleanupValidated(
        app: Context,
        id: String,
        cancelWork: Boolean,
    ): Boolean {
        val root = File(app.noBackupFilesDir, ROOT_NAME)
        if (Files.isSymbolicLink(root.toPath())) return false
        entries(root).remove(id)
        app.revokeUriPermission(
            Uri
                .Builder()
                .scheme("content")
                .authority("${app.packageName}.vault-export")
                .appendPath(id)
                .build(),
            Intent.FLAG_GRANT_READ_URI_PERMISSION,
        )
        val removed = cleanupDirectory(File(root, id))
        if (removed && cancelWork) {
            runCatching { WorkManager.getInstance(app).cancelUniqueWork(CLEANUP_WORK_PREFIX + id) }
        }
        return removed
    }

    private fun scheduleCleanup(
        context: Context,
        id: String,
    ) {
        runCatching {
            val request =
                OneTimeWorkRequestBuilder<VaultExternalCopyCleanupWorker>()
                    .setInitialDelay(1, TimeUnit.MINUTES)
                    .setInputData(androidx.work.workDataOf(VaultExternalCopyCleanupWorker.KEY_ID to id))
                    .build()
            WorkManager.getInstance(context).enqueueUniqueWork(
                CLEANUP_WORK_PREFIX + id,
                ExistingWorkPolicy.REPLACE,
                request,
            )
        }
    }

    private fun resolveEntry(
        context: Context,
        uri: Uri,
    ): Entry? {
        val app = context.applicationContext
        val root = File(app.noBackupFilesDir, ROOT_NAME)
        val (id, entry) =
            validatedId(app, uri)?.let { candidate -> entries(root)[candidate]?.let { candidate to it } } ?: return null
        val expired = entry.expiresAtMillis <= nowMillis()
        if (expired) cleanup(app, id)
        return entry.takeIf { !expired && isSafeFile(root, id, it.file) }
    }

    private fun isSafeFile(
        root: File,
        id: String,
        file: File,
    ): Boolean {
        val directory = File(root, id)
        val safeAncestors = !Files.isSymbolicLink(root.toPath()) && !Files.isSymbolicLink(directory.toPath())
        val safeFile = !Files.isSymbolicLink(file.toPath()) && file.canonicalFile.parentFile == directory.canonicalFile
        return safeAncestors && safeFile && file.isFile
    }

    /** Used by the app startup hook to ensure no previous-process plaintext survives. */
    private fun prepareRoot(context: Context): File {
        val root = File(context.noBackupFilesDir, ROOT_NAME)
        synchronized(processLock) {
            check(root.absolutePath !in unavailableRoots && root.canonicalPath !in unavailableRoots) {
                "Temporary export storage is unavailable."
            }
            check(root.mkdirs() || root.isDirectory) { "Could not prepare temporary exports." }
            check(!Files.isSymbolicLink(root.toPath())) { "Temporary export storage is unavailable." }
            entriesByRoot.putIfAbsent(root.canonicalPath, ConcurrentHashMap())
        }
        return root
    }

    private fun entries(root: File): ConcurrentHashMap<String, Entry> =
        entriesByRoot.computeIfAbsent(root.canonicalPath) { ConcurrentHashMap() }

    private fun nowMillis(): Long = clockForTests?.invoke() ?: SystemClock.elapsedRealtime()

    private fun validatedId(
        context: Context,
        uri: Uri,
    ): String? {
        val contentUri = uri.scheme == "content" && uri.authority == "${context.packageName}.vault-export"
        val exactPath = uri.query == null && uri.fragment == null && uri.pathSegments.size == 1
        return uri.lastPathSegment?.takeIf { contentUri && exactPath && isUuid(it) }
    }

    private fun isUuid(value: String): Boolean =
        runCatching { UUID.fromString(value).toString() == value }.getOrDefault(false)

    private fun safeDisplayName(value: String): String =
        value
            .filterNot { it.isISOControl() }
            .replace('/', '_')
            .replace('\\', '_')
            .trim()
            .take(255)
            .ifBlank { "document" }

    private fun safeMimeType(value: String): String =
        value.lowercase().takeIf { it.matches(MIME_PATTERN) } ?: "application/octet-stream"

    private fun cleanupDirectory(directory: File): Boolean {
        if (cleanupFailureForTests?.invoke(directory) == true) return false
        return when {
            !directory.exists() && !Files.isSymbolicLink(directory.toPath()) -> true
            Files.isSymbolicLink(directory.toPath()) -> directory.delete()
            else ->
                directory.listFiles()?.let { it.all(::cleanupDirectory) && directory.delete() }
                    ?: directory.delete()
        }
    }

    internal const val ROOT_CLEANUP_ID_FOR_WORKER = "__root__"

    private data class Entry(
        val uri: Uri,
        val displayName: String,
        val mimeType: String,
        val expiresAtMillis: Long,
        val file: File,
    ) {
        fun toPublicMetadata() = VaultExternalCopyMetadata(displayName, mimeType, file.length())
    }
}

data class VaultExternalCopyMetadata(
    val displayName: String,
    val mimeType: String,
    val size: Long,
)

class VaultExternalCopyLease internal constructor(
    private val context: Context,
    val uri: Uri,
    private val id: String,
) {
    fun cleanup() = VaultExternalCopyStore.cleanup(context, id)
}
