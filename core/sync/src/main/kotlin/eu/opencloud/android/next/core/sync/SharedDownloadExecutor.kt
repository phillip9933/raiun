package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.IncomingShareStore
import eu.opencloud.android.next.core.database.SharedDownloadRecord
import eu.opencloud.android.next.core.database.SharedDownloadStore
import eu.opencloud.android.next.core.database.SharedLocalFileStore
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.util.UUID

/** Executes a claimed shared download; WorkManager routing and user-visible scheduling remain separate. */
class SharedDownloadExecutor(
    private val database: FileBrowserDatabase,
    private val queue: SharedDownloadQueue,
    private val filesDir: File,
    private val storage: StorageSpaceProvider,
    private val clock: AppClock = SystemAppClock,
) {
    suspend fun execute(
        transferId: String,
        workerId: String,
        client: TransferClient,
        authorization: String,
        progress: (Long) -> Unit = {},
    ) = withContext(Dispatchers.IO) {
        val source = queue.restore(transferId) ?: stale()
        SharedDownloadFiles.guardWriter(filesDir, source.location.accountId) {
            val record = SharedDownloadStore(database).read(transferId) ?: stale()
            if (record.transfer.state != "RUNNING" || record.transfer.workId != workerId) stale()
            requireMatchingSource(record, source)
            if (!IncomingShareStore(database).isCurrent(source.page.checked.lease)) stale()
            if (storage.availableBytes() < source.item.size) throw OpenCloudException(OpenCloudError.LocalStorage)
            val directory = SharedDownloadFiles.directory(filesDir, record.intent.accountId, record.intent.scopeId)
            check(directory.isDirectory || directory.mkdirs()) { "Private download directory is unavailable." }
            val partial = File.createTempFile("download-", ".part", directory)
            val target = File(directory, "${UUID.randomUUID()}.blob")
            var published = false
            try {
                val downloadContext = currentCoroutineContext()
                withRequestCancellation(client::cancelRequests) {
                    download(source, partial, client, authorization, progress)
                    verifyDownloadChecksum(
                        client,
                        DownloadChecksumSource(source.url, authorization, source.expectation),
                        partial,
                        { downloadContext.ensureActive() },
                    )
                }
                currentCoroutineContext().ensureActive()
                check(!target.exists() && partial.renameTo(target)) { "The downloaded file could not be sealed." }
                val commit = SharedFileIntegrity.inspect(directory, target.path, source.item.size, clock.epochMillis())
                val parent = currentCoroutineContext()
                // Finish the commit decision even if cancellation arrives during the database transaction.
                SharedDownloadFiles.guardRead(filesDir, source.location.accountId) {
                    withContext(NonCancellable) {
                        parent.ensureActive()
                        val result =
                            SharedLocalFileStore(database).publish(source.page.checked.lease, record, commit) ?: stale()
                        published = true
                        retirePrevious(directory, target, result.previousLocalPath)
                    }
                }
            } finally {
                partial.delete()
                if (!published) target.delete()
            }
        }
    }

    private fun requireMatchingSource(
        record: SharedDownloadRecord,
        source: PreparedSharedDownload,
    ) {
        val intent = record.intent
        val expected =
            SharedDownloadRequest(
                intent.accountId,
                record.scope.shareId,
                intent.scopeId,
                SharedDownloadFile(intent.remoteId, intent.path, intent.sizeBytes, intent.eTag),
            )
        if (source.request != expected || source.location.binding() != record.scope) stale()
    }

    private fun retirePrevious(
        directory: File,
        target: File,
        path: String?,
    ) {
        try {
            path?.let {
                val previous = File(it).canonicalFile
                if (previous.parentFile == directory && previous != target) previous.delete()
            }
        } catch (_: IOException) {
            // Publication already succeeded. Orphan cleanup can retry without repeating this transfer.
        }
    }

    private suspend fun download(
        source: PreparedSharedDownload,
        partial: File,
        client: TransferClient,
        authorization: String,
        progress: (Long) -> Unit,
    ) {
        val context = currentCoroutineContext()
        val expected = source.item.size
        val responseTag =
            client.download(source.url, authorization, 0, source.expectation) { input, _, _ ->
                FileOutputStream(partial).use { output ->
                    val buffer = ByteArray(64 * 1024)
                    var received = 0L
                    while (true) {
                        context.ensureActive()
                        val count = input.read(buffer)
                        if (count < 0) break
                        if (count == 0 || count.toLong() > expected - received) stale()
                        output.write(buffer, 0, count)
                        received += count
                        progress(received)
                    }
                    if (received != expected) stale()
                    output.fd.sync()
                }
            }
        if (source.item.eTag != null && source.item.eTag != responseTag) stale()
    }

    companion object {
        fun create(context: Context): SharedDownloadExecutor {
            val app = context.applicationContext
            val database = FileBrowserDatabase.create(app)
            val queue = SharedDownloadQueue(SharedDownloadStore(database), SharedDownloadResolver.create(app))
            return SharedDownloadExecutor(database, queue, app.filesDir, AndroidStorageSpaceProvider(app))
        }
    }
}

private fun stale(): Nothing = throw OpenCloudException(OpenCloudError.PreconditionFailed)
