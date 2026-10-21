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
import java.io.InputStream

/** Encrypt first under the live session, then queue an immutable ciphertext payload. */
suspend fun VaultSession.enqueueBackgroundUpload(
    context: Context,
    parentPath: String,
    name: String,
    source: InputStream,
    size: Long,
): String =
    withContext(Dispatchers.IO) {
        val payloads = VaultUploadStore(context)
        val lease = AccountSessions.get(context).beginLease(identity.accountId)
        val job = prepareBackgroundUpload(payloads, parentPath, name, source, size, lease)
        val now = System.currentTimeMillis()
        val store = FileBrowserStore(FileBrowserDatabase.create(context))
        try {
            currentCoroutineContext().ensureActive()
            if (!lease()) throw OpenCloudException(OpenCloudError.AccessDenied)
            val accepted =
                store.enqueueCiphertextUpload(
                    TransferEntity(
                        id = job.id,
                        accountId = job.location.accountId,
                        spaceId = job.location.driveId,
                        resourceId = null,
                        direction = "UPLOAD",
                        sourceUri = null,
                        destinationPath = job.destination,
                        displayName = context.getString(R.string.encrypted_upload),
                        mimeType = "application/octet-stream",
                        bytesTotal = job.size,
                        locationKind = "VAULT",
                        createdAtEpochMillis = now,
                        updatedAtEpochMillis = now,
                    ),
                )
            TransferManager(context, store).scheduleVaultUpload(accepted)
            job.id
        } finally {
            // After the Room commit, startup reconciliation owns scheduling even if this coroutine dies.
            withContext(NonCancellable) {
                val retained = payloads.finishPrepared(job.id) { runBlocking { store.transfer(job.id) != null } }
                if (!retained) store.cancelTransfer(job.id)
            }
        }
    }

fun forgetVaultUploads(
    context: Context,
    accountId: String,
) = VaultUploadStore(context).forgetAccount(accountId)

class VaultUploadWorker internal constructor(
    context: Context,
    params: WorkerParameters,
    private val store: FileBrowserStore,
) : CoroutineWorker(context, params) {
    constructor(context: Context, params: WorkerParameters) : this(
        context,
        params,
        FileBrowserStore(FileBrowserDatabase.create(context)),
    )

    @Suppress("CyclomaticComplexMethod", "ComplexCondition", "TooGenericExceptionCaught", "LongMethod")
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val transferId = inputData.getString(TransferWorker.TRANSFER_ID) ?: return@withContext Result.failure()
            val pending = store.transfer(transferId) ?: return@withContext Result.success()
            if (pending.notBeforeEpochMillis > System.currentTimeMillis()) return@withContext Result.retry()
            val transfer =
                store.claimTransfer(transferId, id.toString(), System.currentTimeMillis())
                    ?: return@withContext unclaimedResult(transferId)
            if (transfer.locationKind != "VAULT" ||
                transfer.direction != "UPLOAD" ||
                transfer.deleteSourceAfterSuccess
            ) {
                return@withContext Result.failure()
            }
            val running =
                transfer.copy(
                    state = "RUNNING",
                    error = null,
                    errorCode = null,
                    notBeforeEpochMillis = 0,
                    attemptCount = transfer.attemptCount + 1,
                    updatedAtEpochMillis = System.currentTimeMillis(),
                )
            if (!store.updateActiveTransfer(running)) return@withContext Result.success()
            val payloads = VaultUploadStore(applicationContext)
            val lease = AccountSessions.get(applicationContext).beginLease(running.accountId)
            val coroutine = currentCoroutineContext()

            var lastPermitCheck = 0L
            var owned = true

            fun permitted(): Boolean {
                coroutine.ensureActive()
                if (!lease()) return false
                val now = android.os.SystemClock.elapsedRealtime()
                if (lastPermitCheck == 0L || now - lastPermitCheck >= 500) {
                    lastPermitCheck = now
                    val latest = runBlocking { store.transfer(transferId) }
                    owned = latest?.workId == id.toString() && latest.state == "RUNNING"
                }
                return owned
            }
            try {
                val job =
                    payloads.read(
                        transferId,
                    ) { if (!permitted()) throw CancellationException("Transfer is no longer active") }
                if (job.location.accountId != running.accountId ||
                    job.location.driveId != running.spaceId ||
                    job.destination != running.destinationPath ||
                    job.size != running.bytesTotal ||
                    job.expectedETag != running.expectedETag ||
                    running.overwrite
                ) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                if (running.bytesTotal >= TransferNotifications.LARGE_TRANSFER_BYTES) {
                    setForeground(
                        TransferNotifications.foregroundInfo(
                            applicationContext,
                            running.id,
                            applicationContext.getString(R.string.encrypted_upload),
                            0,
                            running.bytesTotal,
                        ),
                    )
                }
                var lastUpdate = 0L
                val etag =
                    VaultRepository(applicationContext, store).executePreparedUpload(
                        job,
                        payloads,
                        ::permitted,
                        mayHaveCommitted = running.attemptCount > 1 || running.verificationPending,
                        onMutationStarted = {
                            lastPermitCheck = 0L
                            if (!permitted()) throw CancellationException("Transfer is no longer active")
                            if (!runBlocking { store.updateActiveTransfer(running.copy(verificationPending = true)) }) {
                                throw CancellationException("Transfer is no longer active")
                            }
                        },
                    ) { bytes ->
                        val now = System.currentTimeMillis()
                        if (now - lastUpdate >= 500 || bytes == job.size) {
                            lastUpdate = now
                            if (!runBlocking { store.updateTransferProgress(running, bytes, now) }) {
                                throw CancellationException("Transfer is no longer active")
                            }
                        }
                    }
                lastPermitCheck = 0L
                if (!permitted()) throw CancellationException("Transfer is no longer active")
                val completed =
                    store.updateActiveTransfer(
                        running.copy(
                            state = "SUCCEEDED",
                            bytesTransferred = job.size,
                            verifiedETag = etag,
                            verificationPending = false,
                            error = null,
                            errorCode = null,
                            updatedAtEpochMillis = System.currentTimeMillis(),
                        ),
                    )
                if (completed) payloads.delete(transferId)
                Result.success()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                val mapped = error.toOpenCloudError()
                val latest = store.transfer(transferId) ?: return@withContext Result.success()
                if (latest.workId != running.workId || latest.state != "RUNNING") return@withContext Result.success()
                val retry = mapped.canRetryTransfer(running)
                store.updateActiveTransfer(
                    latest.copy(
                        state =
                            if (retry) {
                                "RETRY"
                            } else if (mapped == OpenCloudError.Conflict) {
                                "CONFLICT"
                            } else {
                                "FAILED"
                            },
                        error = mapped.safeMessage(applicationContext),
                        errorCode = mapped.diagnosticCode(),
                        verificationPending = latest.verificationPending || latest.bytesTransferred > 0,
                        notBeforeEpochMillis = if (retry) mapped.retryDeadline(System.currentTimeMillis()) else 0,
                        updatedAtEpochMillis = System.currentTimeMillis(),
                    ),
                )
                if (retry) Result.retry() else Result.failure()
            }
        }

    private suspend fun unclaimedResult(transferId: String): Result {
        val current = store.transfer(transferId)
        val sameWorker = current?.workId == null || current.workId == id.toString()
        return if (sameWorker && current?.state in setOf("QUEUED", "RUNNING", "RETRY")) {
            Result.retry()
        } else {
            Result.success()
        }
    }
}
