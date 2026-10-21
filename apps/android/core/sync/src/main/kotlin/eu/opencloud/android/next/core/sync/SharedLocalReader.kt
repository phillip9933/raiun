package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.SharedFolderEntry
import eu.opencloud.android.next.core.database.SharedLocalFile
import eu.opencloud.android.next.core.database.SharedLocalFileStore
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.concurrent.atomic.AtomicBoolean

/** Content authorization must check this descendant on the server, not just the shared root's permissions. */
class SharedLocalReader(
    private val database: FileBrowserDatabase,
    private val resolver: SharedDownloadResolver,
    private val filesDir: File,
    private val authorizeContent: suspend (PreparedSharedDownload) -> Unit,
    private val localAccess: () -> Boolean,
) {
    private val copies = SharedLocalFileStore(database)

    suspend fun open(request: SharedDownloadRequest): SharedReadSession {
        var pending: SharedReadSession? = null
        var delivered = false
        try {
            val session =
                withContext(Dispatchers.IO) {
                    createSession(request).also { pending = it }
                }
            delivered = true
            return session
        } finally {
            if (!delivered) pending?.close()
        }
    }

    suspend fun setOfflinePinned(
        request: SharedDownloadRequest,
        pinned: Boolean,
    ) = withContext(Dispatchers.IO) {
        withVerifiedCopy(request) { binding ->
            if (!copies.setPinned(binding.source.page.checked.lease, binding.entry, binding.copy, pinned)) staleRead()
        }
    }

    /** Only private local bytes are removed. No server request or remote deletion occurs. */
    suspend fun removeLocalCopy(expected: SharedLocalFile): Boolean =
        withContext(Dispatchers.IO) {
            requireLocalAccess()
            SharedDownloadFiles.guardRead(filesDir, expected.accountId) {
                requireLocalAccess()
                val directory = SharedDownloadFiles.directory(filesDir, expected.accountId, expected.scopeId)
                val file = File(expected.localPath).canonicalFile
                if (file.parentFile != directory) staleRead()
                if (!copies.remove(expected)) return@guardRead false
                // Metadata is removed first; interrupted deletion leaves an unreachable orphan for maintenance.
                if (file.exists() && !file.delete()) throw IOException("The local shared copy could not be removed.")
                true
            }
        }

    private suspend fun createSession(request: SharedDownloadRequest): SharedReadSession =
        withVerifiedCopy(request) { binding ->
            val account = SharedDownloadFiles.accountDirectory(filesDir, request.accountId)
            val lease = SharedReadLeases.acquire(account, binding.copy.localPath)
            SharedReadSession(binding.copy.sizeBytes, lease::close) { offset, count -> read(binding, offset, count) }
        }

    private suspend fun <T> withVerifiedCopy(
        request: SharedDownloadRequest,
        action: suspend (ReadBinding) -> T,
    ): T {
        requireLocalAccess()
        val source = resolver.prepare(request)
        authorizeContent(source)
        return SharedDownloadFiles.guardRead(filesDir, request.accountId) {
            requireLocalAccess()
            val entry =
                database.sharedFolderCacheDao().entry(request.accountId, request.scopeId, request.file.remoteId)
                    ?: staleRead()
            val selected = SharedDownloadFile(entry.remoteId, entry.path, entry.sizeBytes, entry.eTag)
            if (selected != request.file) staleRead()
            if (database.sharedLocalFileDao().find(request.accountId, request.scopeId, request.file.remoteId) == null) {
                throw SharedCopyUnavailable()
            }
            val copy = copies.read(source.page.checked.lease, entry) ?: staleRead()
            val directory = SharedDownloadFiles.directory(filesDir, request.accountId, request.scopeId)
            if (!SharedFileIntegrity.matches(directory, copy)) throw SharedCopyUnavailable()
            requireCurrent(source, entry, copy)
            action(ReadBinding(source, entry, copy, directory))
        }
    }

    private suspend fun read(
        binding: ReadBinding,
        offset: Long,
        count: Int,
    ): ByteArray =
        withContext(Dispatchers.IO) {
            val source = binding.source
            val entry = binding.entry
            val copy = binding.copy
            val directory = binding.directory
            SharedDownloadFiles.guardRead(filesDir, copy.accountId) {
                requireCurrent(source, entry, copy)
                val file = validatedCachedFile(directory, copy.localPath, copy.sizeBytes) ?: staleRead()
                val available = (copy.sizeBytes - offset).coerceAtLeast(0).coerceAtMost(count.toLong()).toInt()
                val bytes = ByteArray(available)
                RandomAccessFile(file, "r").use {
                    it.seek(offset)
                    it.readFully(bytes)
                }
                requireCurrent(source, entry, copy)
                bytes
            }
        }

    private data class ReadBinding(
        val source: PreparedSharedDownload,
        val entry: SharedFolderEntry,
        val copy: SharedLocalFile,
        val directory: File,
    )

    private suspend fun requireCurrent(
        source: PreparedSharedDownload,
        entry: SharedFolderEntry,
        copy: SharedLocalFile,
    ) {
        requireLocalAccess()
        if (copies.read(source.page.checked.lease, entry) != copy) staleRead()
        requireLocalAccess()
    }

    private suspend fun requireLocalAccess() {
        currentCoroutineContext().ensureActive()
        if (!localAccess()) throw OpenCloudException(OpenCloudError.AccessDenied)
    }

    companion object {
        /** Capture a fresh revision-bound permit for each open, including opens from Android's document picker. */
        suspend fun open(
            context: Context,
            request: SharedDownloadRequest,
        ): SharedReadSession = create(context).open(request)

        /** Caller obtains a new instance for each user action; permissions are never restored across relocking. */
        fun create(context: Context): SharedLocalReader {
            val app = context.applicationContext
            val permit = AppLock(app).beginDocumentRead()
            val resolver = SharedDownloadResolver.create(app)
            return SharedLocalReader(
                FileBrowserDatabase.create(app),
                resolver,
                app.filesDir,
                { source ->
                    val account = source.page.checked.lease.account
                    val authorization = WorkerAuthorizationProvider(app).authorization(account)
                    if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
                    if (!resolver.isCurrent(source)) staleRead()
                    val http = TlsPolicy(app).applyTo(OkHttpClient(), account.serverUrl)
                    authorizeSharedContent(source, TransferClient(http), authorization)
                },
                permit,
            )
        }
    }
}

/** No raw file path or descriptor escapes; each bounded read rechecks local authorization and current metadata. */
class SharedReadSession internal constructor(
    val size: Long,
    private val onClose: () -> Unit,
    private val readBytes: suspend (Long, Int) -> ByteArray,
) : AutoCloseable {
    private val closed = AtomicBoolean()

    suspend fun read(
        offset: Long,
        count: Int,
    ): ByteArray {
        require(offset >= 0 && count in 0..65_536)
        check(!closed.get()) { "The shared read session is closed." }
        var completed = false
        try {
            val bytes = readBytes(offset, count)
            check(!closed.get()) { "The shared read session is closed." }
            completed = true
            return bytes
        } finally {
            if (!completed) close()
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) onClose()
    }
}

private fun staleRead(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)

internal class SharedCopyUnavailable : OpenCloudException(OpenCloudError.LocalStorage)
