package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.AccountSessions
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext

suspend fun VaultSession.enqueueBackgroundOfflineDownload(
    context: Context,
    entry: VaultFolder,
): String =
    withContext(Dispatchers.IO) {
        val payloads = VaultDownloadStore(context)
        val lease = AccountSessions.get(context).beginLease(identity.accountId)
        ensureOfflineUnlockAnchor(VaultOfflineStore(context))
        val job = captureBackgroundDownload(payloads, entry)
        val store = FileBrowserStore(FileBrowserDatabase.create(context))
        try {
            currentCoroutineContext().ensureActive()
            if (!lease()) throw OpenCloudException(OpenCloudError.AccessDenied)
            val now = System.currentTimeMillis()
            val accepted =
                store.enqueueCiphertextDownload(
                    TransferEntity(
                        id = job.id,
                        accountId = identity.accountId,
                        spaceId = identity.driveId,
                        resourceId = job.source.id,
                        direction = "DOWNLOAD",
                        sourceUri = "vault-offline:${identity.remoteVaultId}",
                        destinationPath = job.source.relativePath,
                        displayName = context.getString(R.string.encrypted_offline_download),
                        mimeType = "application/octet-stream",
                        bytesTotal = job.source.size,
                        offlinePin = true,
                        expectedETag = job.source.strongETag,
                        locationKind = "VAULT",
                        createdAtEpochMillis = now,
                        updatedAtEpochMillis = now,
                    ),
                )
            TransferManager(context, store).scheduleVaultDownload(accepted)
            job.id
        } finally {
            withContext(NonCancellable) {
                val retained = payloads.finishPrepared(job.id) { runBlocking { store.transfer(job.id) != null } }
                if (!retained) store.cancelTransfer(job.id)
            }
        }
    }

/** Authenticates only jobs belonging to this live root; changed jobs become actionable failures. */
suspend fun VaultSession.completePendingOfflineDownloads(
    context: Context,
    offline: VaultOfflineStore,
) = completeVaultPendingDownloads(
    context,
    identity,
) { job, payloads, permit, commit -> publishBackgroundDownload(job, payloads, offline, permit, commit) }

suspend fun VaultOfflineSession.completePendingOfflineDownloads(
    context: Context,
    offline: VaultOfflineStore,
) = completeVaultPendingDownloads(
    context,
    identity,
) { job, payloads, permit, commit -> publishBackgroundDownload(job, payloads, offline, permit, commit) }

// Admission, authentication and CAS publication share one cancellation scope.
@Suppress("TooGenericExceptionCaught", "CyclomaticComplexMethod", "LongParameterList")
// Injectable ownership/store seams keep publication and Room CAS regression tests independent of transport.
internal suspend fun completeVaultPendingDownloads(
    context: Context,
    identity: eu.opencloud.android.next.core.security.VaultIdentity,
    store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
    payloads: VaultDownloadStore = VaultDownloadStore(context),
    lease: () -> Boolean = AccountSessions.get(context).beginLease(identity.accountId),
    publish: suspend (VaultDownloadJob, VaultDownloadStore, () -> Boolean, suspend () -> Boolean) -> Unit,
) = withContext(Dispatchers.IO) {
    val coroutine = currentCoroutineContext()
    var afterId = ""
    while (true) {
        val pending =
            store.awaitingCiphertextDownloadsPage(
                identity.accountId,
                "vault-offline:${identity.remoteVaultId}",
                afterId,
                128,
            )
        if (pending.isEmpty()) break
        for (transfer in pending) {
            if (!VaultDownloadStore.publishing.add(transfer.id)) continue
            val attempt = payloads.beginAttempt(transfer.id, transfer.accountId)
            try {
                val job = payloads.read(transfer.id)
                if (job.location.remoteVaultId != identity.remoteVaultId ||
                    job.location.canonicalServer != identity.canonicalServer
                ) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                requireDownloadDescriptor(job, transfer)
                var lastCheck = 0L
                var owned = true

                fun permitted(): Boolean {
                    coroutine.ensureActive()
                    if (!lease() || !attempt.isActive) return false
                    val now = android.os.SystemClock.elapsedRealtime()
                    if (lastCheck == 0L || now - lastCheck >= 500) {
                        lastCheck = now
                        owned = runBlocking { store.transfer(transfer.id) } == transfer
                    }
                    return owned
                }
                publish(job, payloads, ::permitted) {
                    lastCheck = 0L
                    if (!permitted()) throw OpenCloudException(OpenCloudError.AccessDenied)
                    store.completeAwaitingCiphertextDownload(
                        transfer,
                        transfer.copy(
                            state = "SUCCEEDED",
                            verificationPending = false,
                            error = null,
                            errorCode = null,
                            updatedAtEpochMillis = System.currentTimeMillis(),
                        ),
                    )
                }
                payloads.delete(job.id)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                coroutine.ensureActive()
                val mapped = error.toOpenCloudError()
                store.completeAwaitingCiphertextDownload(
                    transfer,
                    transfer.copy(
                        state = "FAILED",
                        error = mapped.safeMessage(context),
                        errorCode = mapped.diagnosticCode(),
                        updatedAtEpochMillis = System.currentTimeMillis(),
                    ),
                )
            } finally {
                attempt.close()
                VaultDownloadStore.publishing.remove(transfer.id)
            }
        }
        afterId = pending.last().id
    }
}

fun forgetVaultDownloads(
    context: Context,
    accountId: String,
) = VaultDownloadStore(context).forgetAccount(accountId)

internal interface VaultDownloadExecution {
    fun beginLease(accountId: String): () -> Boolean

    suspend fun download(
        job: VaultDownloadJob,
        payloads: VaultDownloadStore,
        permit: () -> Boolean,
        progress: (Long) -> Unit,
    ): Long
}

class VaultDownloadWorker internal constructor(
    context: Context,
    params: WorkerParameters,
    private val store: FileBrowserStore,
    private val payloads: VaultDownloadStore,
    private val execution: VaultDownloadExecution,
) : CoroutineWorker(context, params) {
    constructor(context: Context, params: WorkerParameters) : this(
        context,
        params,
        FileBrowserStore(FileBrowserDatabase.create(context)),
        VaultDownloadStore(context),
        object : VaultDownloadExecution {
            override fun beginLease(accountId: String) = AccountSessions.get(context).beginLease(accountId)

            override suspend fun download(
                job: VaultDownloadJob,
                payloads: VaultDownloadStore,
                permit: () -> Boolean,
                progress: (Long) -> Unit,
            ) = VaultRepository(context, FileBrowserStore(FileBrowserDatabase.create(context)))
                .executePreparedDownload(job, payloads, permit, progress)
        },
    )

    private suspend fun unclaimedDownloadResult(
        store: FileBrowserStore,
        transferId: String,
    ): Result {
        val current = store.transfer(transferId)
        val sameWorker = current?.workId == null || current.workId == id.toString()
        return if (sameWorker && current?.state in setOf("QUEUED", "RUNNING", "RETRY")) {
            Result.retry()
        } else {
            Result.success()
        }
    }

    @Suppress("TooGenericExceptionCaught", "CyclomaticComplexMethod")
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val transferId = inputData.getString(TransferWorker.TRANSFER_ID) ?: return@withContext Result.failure()
            val pending = store.transfer(transferId) ?: return@withContext Result.success()
            if (pending.notBeforeEpochMillis > System.currentTimeMillis()) return@withContext Result.retry()
            val transfer =
                store.claimTransfer(transferId, id.toString(), System.currentTimeMillis())
                    ?: return@withContext unclaimedDownloadResult(store, transferId)
            val running =
                transfer.copy(
                    state = "RUNNING",
                    attemptCount = transfer.attemptCount + 1,
                    error = null,
                    errorCode = null,
                    notBeforeEpochMillis = 0,
                    updatedAtEpochMillis = System.currentTimeMillis(),
                )
            if (running.locationKind != "VAULT" ||
                running.direction != "DOWNLOAD" ||
                !running.offlinePin
            ) {
                return@withContext Result.failure()
            }
            if (!store.updateActiveTransfer(running)) return@withContext Result.success()
            val lease = execution.beginLease(running.accountId)
            val coroutine = currentCoroutineContext()
            var lastCheck = 0L
            var owned = true
            val attempt = payloads.beginAttempt(transferId, running.accountId)

            fun permitted(): Boolean {
                coroutine.ensureActive()
                if (!lease() || !attempt.isActive) return false
                val now = android.os.SystemClock.elapsedRealtime()
                if (lastCheck == 0L || now - lastCheck >= 500) {
                    lastCheck = now
                    val latest = runBlocking { store.transfer(transferId) }
                    owned = latest != null && latest.workId == running.workId && latest.state == "RUNNING"
                }
                return owned
            }
            try {
                val job = payloads.read(transferId)
                requireDownloadDescriptor(job, running)
                if (running.bytesTotal >= TransferNotifications.LARGE_TRANSFER_BYTES) {
                    setForeground(
                        TransferNotifications.foregroundInfo(
                            applicationContext,
                            running.id,
                            applicationContext.getString(R.string.encrypted_offline_download),
                            0,
                            running.bytesTotal,
                        ),
                    )
                }
                var lastProgress = 0L
                val size =
                    execution.download(job, payloads, ::permitted) { bytes ->
                        val now = System.currentTimeMillis()
                        if (now - lastProgress >= 500 || bytes == job.source.size) {
                            lastProgress = now
                            if (!runBlocking {
                                    store.updateTransferProgress(running, bytes, now)
                                }
                            ) {
                                throw CancellationException("Transfer is no longer active")
                            }
                        }
                    }
                lastCheck = 0L
                if (!permitted()) throw CancellationException("Transfer is no longer active")
                store.updateActiveTransfer(
                    running.copy(
                        state = "AWAITING_UNLOCK",
                        bytesTransferred = size,
                        verificationPending = true,
                        updatedAtEpochMillis = System.currentTimeMillis(),
                    ),
                )
                Result.success()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                val latest = store.transfer(transferId) ?: return@withContext Result.success()
                if (latest.workId != running.workId || latest.state != "RUNNING") return@withContext Result.success()
                val mapped = error.toOpenCloudError()
                val retry = mapped.canRetryTransfer(running)
                store.updateActiveTransfer(
                    latest.copy(
                        state = if (retry) "RETRY" else "FAILED",
                        error = mapped.safeMessage(applicationContext),
                        errorCode = mapped.diagnosticCode(),
                        notBeforeEpochMillis = if (retry) mapped.retryDeadline(System.currentTimeMillis()) else 0,
                        updatedAtEpochMillis = System.currentTimeMillis(),
                    ),
                )
                if (retry) Result.retry() else Result.failure()
            } finally {
                attempt.close()
            }
        }
}

private fun requireDownloadDescriptor(
    job: VaultDownloadJob,
    row: TransferEntity,
) {
    val scopeMatches =
        job.location.accountId == row.accountId &&
            job.location.driveId == row.spaceId &&
            row.sourceUri == "vault-offline:${job.location.remoteVaultId}"
    val sourceMatches =
        listOf(job.source.relativePath, job.source.id, job.source.strongETag) ==
            listOf(row.destinationPath, row.resourceId, row.expectedETag)
    if (!scopeMatches || !sourceMatches || job.source.size != row.bytesTotal) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}
