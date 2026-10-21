package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.network.ContentFingerprint
import eu.opencloud.android.next.core.network.TransferClient
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.io.File

internal class IncomingFolderUploadExecutor(
    private val queue: IncomingFolderUploadQueue,
    private val store: FileBrowserStore,
    private val client: TransferClient,
    private val clock: AppClock = SystemAppClock,
) {
    private suspend fun updatePrepared(transfer: TransferEntity) {
        if (!store.updateActiveTransfer(transfer)) throw CancellationException("Transfer is no longer active")
    }

    suspend fun execute(
        transfer: TransferEntity,
        staged: File,
        authorization: String,
        progress: (TransferEntity, Long) -> Unit,
    ) {
        val coroutine = currentCoroutineContext()
        val prepared = transfer.copy(bytesTotal = staged.length())
        updatePrepared(prepared)
        val destination = queue.prepare(prepared)
        val url =
            destination.webDavUrl
                .toHttpUrl()
                .newBuilder()
                .addPathSegment(prepared.displayName)
                .build()
                .toString()
        val fingerprint =
            staged.inputStream().use {
                ContentFingerprint.read(it, prepared.bytesTotal) { coroutine.ensureActive() }
            }
        var verifiedETag: String? = null
        uploadAndVerify(
            prepared,
            upload = {
                client.upload(
                    url,
                    authorization,
                    prepared.mimeType,
                    prepared.bytesTotal,
                    false,
                    { staged.inputStream() },
                ) {
                    progress(prepared, it)
                }
            },
            uploaded = {
                if (!store.updateActiveTransfer(
                        prepared.copy(bytesTransferred = prepared.bytesTotal, verificationPending = true),
                    )
                ) {
                    throw CancellationException("Transfer is no longer active")
                }
            },
            verify = {
                verifiedETag =
                    client.verifyUpload(url, authorization, fingerprint, useServerChecksum = true) {
                        coroutine.ensureActive()
                    }
            },
        )
        val checked = queue.prepare(prepared)
        if (!queue.complete(prepared, checked, verifiedETag, clock.epochMillis())) {
            throw CancellationException("Transfer is no longer active")
        }
    }
}
