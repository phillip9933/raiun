package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.TransferState
import eu.opencloud.android.next.core.datastore.LocalDiagnostics
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.datastore.TransferDiagnostic
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.model.cacheIdentity
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.network.ContentFingerprint
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.network.TransferConflictException
import eu.opencloud.android.next.core.network.TransferHttpException
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.io.File
import java.io.FileOutputStream
import java.util.Base64
import java.util.concurrent.TimeUnit

abstract class TransferWorker(
    context: Context,
    params: WorkerParameters,
    protected val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
    private val clock: AppClock = SystemAppClock,
    private val network: NetworkStatus = AndroidNetworkStatus(context),
    protected val storage: StorageSpaceProvider = AndroidStorageSpaceProvider(context),
) : CoroutineWorker(context, params) {
    protected open val supportsSharedDownloads: Boolean = false
    protected open val supportsSharedUploads: Boolean = false

    @Suppress("CyclomaticComplexMethod", "TooGenericExceptionCaught")
    final override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val transferId = inputData.getString(TRANSFER_ID) ?: return@withContext Result.failure()
            val pending = store.transfer(transferId) ?: return@withContext Result.failure()
            if (pending.state !in setOf("QUEUED", "RUNNING", "RETRY")) return@withContext Result.success()
            if (pending.workId != null && pending.workId != id.toString()) return@withContext Result.success()
            if (pending.notBeforeEpochMillis > now()) return@withContext Result.retry()
            val transfer =
                store.claimTransfer(transferId, id.toString(), now())
                    ?: return@withContext unclaimedResult(transferId)
            val account =
                store.account(transfer.accountId) ?: return@withContext fail(transfer, "The account is unavailable.")
            val shared = transfer.locationKind == "SHARED_FOLDER"
            val supportedShared =
                if (transfer.direction ==
                    "DOWNLOAD"
                ) {
                    supportsSharedDownloads
                } else {
                    supportsSharedUploads
                }
            if (transfer.locationKind != "SPACE" && !(shared && supportedShared)) {
                return@withContext fail(transfer, "This transfer location is not supported yet.", "UNSUPPORTED")
            }
            val space = if (shared) null else store.space(transfer.accountId, transfer.spaceId)
            if (!shared && space == null) return@withContext fail(transfer, "The space is unavailable.")
            if (space?.isDisabled == true || space?.isDeleted == true) {
                return@withContext fail(transfer, "This space is unavailable for transfers.", "ACCESS_DENIED")
            }
            val running =
                transfer.copy(
                    state = TransferState.RUNNING.name,
                    attemptCount = transfer.attemptCount + 1,
                    bytesTransferred = if (shared && transfer.direction == "DOWNLOAD") 0 else transfer.bytesTransferred,
                    updatedAtEpochMillis = now(),
                )
            if (!store.updateActiveTransfer(running)) return@withContext Result.success()
            if (running.deleteSourceAfterSuccess) {
                return@withContext fail(running, "Turn off source deletion before retrying this upload.", "UNSUPPORTED")
            }
            try {
                if (!network.isConnected()) throw OpenCloudException(OpenCloudError.Connectivity)
                if (running.bytesTotal < 0 || running.bytesTotal >= TransferNotifications.LARGE_TRANSFER_BYTES) {
                    setForeground(
                        TransferNotifications.foregroundInfo(
                            applicationContext,
                            running.id,
                            running.displayName,
                            running.bytesTransferred,
                            running.bytesTotal,
                        ),
                    )
                }
                val transferClient = client(account)
                withRequestCancellation(transferClient::cancelRequests, isOwned = {
                    val current = store.transfer(running.id)
                    current?.workId == running.workId &&
                        current?.state in setOf(TransferState.RUNNING.name, TransferState.SUCCEEDED.name)
                }) {
                    if (shared) {
                        executeShared(running, transferClient, authorization(account))
                    } else {
                        execute(running, account, requireNotNull(space), transferClient, authorization(account))
                    }
                }
                currentCoroutineContext().ensureActive()
                if (!complete(running, shared)) throw CancellationException("Transfer is no longer active")
                LocalDiagnostics.record(applicationContext, TransferDiagnostic.SUCCEEDED)
                notifyDocumentsProvider()
                Result.success()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: TransferConflictException) {
                val latest = ownedCurrent(running)
                store.updateActiveTransfer(
                    latest.copy(
                        state = TransferState.CONFLICT.name,
                        error = "An item with this name already exists.",
                        errorCode = "CONFLICT",
                        updatedAtEpochMillis = now(),
                    ),
                )
                Result.failure()
            } catch (error: Exception) {
                currentCoroutineContext().ensureActive()
                val failure = error.toOpenCloudError()
                val latest = ownedCurrent(running)
                LocalDiagnostics.record(
                    applicationContext,
                    if (failure == OpenCloudError.AuthenticationRequired) {
                        TransferDiagnostic.AUTHENTICATION_REQUIRED
                    } else if (failure.canRetryTransfer(latest)) {
                        TransferDiagnostic.RETRY
                    } else {
                        TransferDiagnostic.FAILED
                    },
                )
                if (failure in
                    setOf(OpenCloudError.AccessDenied, OpenCloudError.NotFound, OpenCloudError.HttpFailure(405))
                ) {
                    CapabilityRepository.get(applicationContext).invalidate(account.id)
                }
                if (failure.canRetryTransfer(latest)) {
                    store.updateActiveTransfer(
                        latest.copy(
                            state = TransferState.RETRY.name,
                            error = failure.safeMessage(),
                            errorCode = failure.diagnosticCode(),
                            notBeforeEpochMillis = failure.retryDeadline(now()),
                            updatedAtEpochMillis = now(),
                        ),
                    )
                    Result.retry()
                } else {
                    fail(latest, failure.safeMessage(), failure.diagnosticCode())
                }
            }
        }

    private suspend fun ownedCurrent(running: TransferEntity): TransferEntity {
        val latest = store.transfer(running.id)
        if (latest == null || latest.workId != running.workId) throw CancellationException("Worker ownership changed")
        return latest
    }

    private suspend fun complete(
        running: TransferEntity,
        shared: Boolean,
    ): Boolean {
        val latest = store.transfer(running.id)
        if (latest == null || latest.workId != running.workId) return false
        return if (shared) {
            latest.state == "SUCCEEDED"
        } else {
            store.updateActiveTransfer(
                latest.copy(
                    state = TransferState.SUCCEEDED.name,
                    bytesTransferred = latest.bytesTotal,
                    error = null,
                    errorCode = null,
                    notBeforeEpochMillis = 0,
                    updatedAtEpochMillis = now(),
                ),
            )
        }
    }

    protected abstract suspend fun execute(
        transfer: TransferEntity,
        account: AccountEntity,
        space: SpaceEntity,
        client: TransferClient,
        authorization: String,
    )

    protected open suspend fun executeShared(
        transfer: TransferEntity,
        client: TransferClient,
        authorization: String,
    ): Unit = throw OpenCloudException(OpenCloudError.PreconditionFailed)

    private suspend fun unclaimedResult(transferId: String): Result {
        val current = store.transfer(transferId)
        val sameWorker = current?.workId == null || current.workId == id.toString()
        return if (sameWorker &&
            current?.state in setOf("QUEUED", "RUNNING", "RETRY")
        ) {
            Result.retry()
        } else {
            Result.success()
        }
    }

    protected open fun authorization(account: AccountEntity): String =
        WorkerAuthorizationProvider(applicationContext).authorization(account)

    protected suspend fun checkpoint(
        transfer: TransferEntity,
        bytes: Long,
        tusUrl: String? = transfer.tusUrl,
    ) {
        currentCoroutineContext().ensureActive()
        val updated =
            store.updateActiveTransfer(
                transfer.copy(
                    bytesTransferred = bytes,
                    tusOffset = bytes,
                    tusUrl = tusUrl,
                    verificationPending =
                        transfer.verificationPending ||
                            (transfer.direction == "UPLOAD" && bytes == transfer.bytesTotal),
                    updatedAtEpochMillis = now(),
                ),
            )
        if (!updated) throw CancellationException("Transfer is no longer active")
        if (transfer.bytesTotal >= TransferNotifications.LARGE_TRANSFER_BYTES) {
            setForeground(
                TransferNotifications.foregroundInfo(
                    applicationContext,
                    transfer.id,
                    transfer.displayName,
                    bytes,
                    transfer.bytesTotal,
                ),
            )
        }
    }

    private var lastProgressTime = 0L

    protected fun updateForegroundProgress(
        transfer: TransferEntity,
        bytes: Long,
    ) {
        val elapsed = android.os.SystemClock.elapsedRealtime()
        if (elapsed - lastProgressTime < 500 && bytes != transfer.bytesTotal) return
        lastProgressTime = elapsed
        kotlinx.coroutines.runBlocking {
            if (!store.updateTransferProgress(transfer, bytes, now())) {
                throw CancellationException("Transfer is no longer active")
            }
        }
        if (transfer.bytesTotal >= TransferNotifications.LARGE_TRANSFER_BYTES) {
            setForegroundAsync(
                TransferNotifications.foregroundInfo(
                    applicationContext,
                    transfer.id,
                    transfer.displayName,
                    bytes,
                    transfer.bytesTotal,
                ),
            )
        }
    }

    private suspend fun fail(
        transfer: TransferEntity,
        message: String,
        code: String = "PRECONDITION",
    ): Result {
        store.updateActiveTransfer(
            transfer.copy(
                state = TransferState.FAILED.name,
                error = message,
                errorCode = code,
                updatedAtEpochMillis = now(),
            ),
        )
        return Result.failure()
    }

    protected open fun client(account: AccountEntity): TransferClient {
        val base =
            OkHttpClient
                .Builder()
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(60, TimeUnit.SECONDS)
                .build()
        return TransferClient(TlsPolicy(applicationContext).applyTo(base, account.serverUrl))
    }

    protected fun now() = clock.epochMillis()

    private fun notifyDocumentsProvider() {
        applicationContext.contentResolver.notifyChange(
            DocumentsContract.buildRootsUri("${applicationContext.packageName}.documents"),
            null,
        )
    }

    companion object {
        const val TRANSFER_ID = "transferId"
    }
}

class UploadWorker(
    context: Context,
    params: WorkerParameters,
) : TransferWorker(context, params) {
    override val supportsSharedUploads: Boolean = true

    override suspend fun executeShared(
        transfer: TransferEntity,
        client: TransferClient,
        authorization: String,
    ) {
        val queue = IncomingFolderUploadQueue.create(applicationContext)
        queue.prepare(transfer)
        val coroutine = currentCoroutineContext()
        val directory =
            File(
                applicationContext.noBackupFilesDir,
                "upload-sources/${cacheIdentity(transfer.accountId)}/${cacheIdentity(transfer.id)}",
            )
        PrivateCacheUse.hold(uploadSourceFiles(directory)) {
            val sourceUri = Uri.parse(requireNotNull(transfer.sourceUri))
            val staged =
                stageUploadSource(
                    directory,
                    uploadStagingExpectedLength(applicationContext, sourceUri, transfer.bytesTotal),
                    { openUploadSource(applicationContext, sourceUri) },
                    storage::availableBytes,
                ) { coroutine.ensureActive() }
            IncomingFolderUploadExecutor(
                queue,
                store,
                client,
            ).execute(transfer, staged, authorization, ::updateForegroundProgress)
        }
    }

    override suspend fun execute(
        transfer: TransferEntity,
        account: AccountEntity,
        space: SpaceEntity,
        client: TransferClient,
        authorization: String,
    ) {
        val coroutine = currentCoroutineContext()
        val sourceUri = Uri.parse(requireNotNull(transfer.sourceUri))
        val sourceDirectory =
            File(
                applicationContext.noBackupFilesDir,
                "upload-sources/${cacheIdentity(transfer.accountId)}/${cacheIdentity(transfer.id)}",
            )
        PrivateCacheUse.hold(uploadSourceFiles(sourceDirectory)) {
            val staged =
                stageUploadSource(
                    sourceDirectory,
                    uploadStagingExpectedLength(applicationContext, sourceUri, transfer.bytesTotal),
                    { openUploadSource(applicationContext, sourceUri) },
                    storage::availableBytes,
                ) { coroutine.ensureActive() }
            val prepared = transfer.copy(bytesTotal = staged.length()).withoutUnprotectedTusSession()
            if (!store.updateActiveTransfer(prepared)) throw CancellationException("Transfer is no longer active")
            uploadPrepared(prepared, account, space, client, authorization, staged)
        }
    }

    @Suppress("LongParameterList")
    private suspend fun uploadPrepared(
        transfer: TransferEntity,
        account: AccountEntity,
        space: SpaceEntity,
        client: TransferClient,
        authorization: String,
        staged: File,
    ) {
        val root = webDavRoot(space)
        val capabilities = CapabilityRepository.get(applicationContext).refresh(account, authorization, store)
        val destinationUrl = root.childUrl(transfer.destinationPath)
        val source = { staged.inputStream() }
        val coroutineContext = currentCoroutineContext()
        val fingerprint =
            source().use {
                ContentFingerprint.read(it, transfer.bytesTotal) { coroutineContext.ensureActive() }
            }
        val upload: suspend () -> String? = {
            if (transfer.canUseTusUpload(capabilities.tusSupported)) {
                uploadTus(
                    transfer,
                    account,
                    root.childUrl(transfer.destinationPath.substringBeforeLast('/', "")),
                    client,
                    source,
                )
                null
            } else {
                client.upload(
                    destinationUrl,
                    authorization,
                    transfer.mimeType,
                    transfer.bytesTotal,
                    transfer.overwrite,
                    source,
                    expectedETag = transfer.expectedETag,
                ) { bytes -> updateForegroundProgress(transfer, bytes) }
            }
        }
        var verifiedETag: String? = null
        uploadAndVerify(
            transfer,
            upload = {
                try {
                    upload()
                } catch (exception: TransferHttpException) {
                    if (transfer.expectedETag != null || exception.statusCode !in setOf(404, 409)) throw exception
                    createMissingDestinationDirectories(
                        root = root,
                        destinationPath = transfer.destinationPath,
                        client = client,
                        authorization = authorization,
                    )
                    upload()
                }
            },
            uploaded = { checkpoint(transfer, transfer.bytesTotal) },
            recreateMissing = {
                // The server confirmed absence. If-None-Match protects a racing creator;
                // never reuse an ambiguous TUS session for this recovery.
                client.upload(
                    destinationUrl,
                    authorization,
                    transfer.mimeType,
                    transfer.bytesTotal,
                    false,
                    source,
                ) { bytes -> updateForegroundProgress(transfer, bytes) }
            },
            verify = {
                verifiedETag =
                    client.verifyUpload(destinationUrl, authorization, fingerprint, useServerChecksum = true) {
                        coroutineContext.ensureActive()
                    }
            },
        )
        checkpoint(transfer, transfer.bytesTotal)
        val verified = requireNotNull(store.transfer(transfer.id)).copy(verifiedETag = verifiedETag)
        if (!store.updateActiveTransfer(verified)) throw CancellationException("Transfer is no longer active")
        if (store.completeUpload(transfer)) {
            TransferManager(
                applicationContext,
                store,
            ).reconcileDiscovery()
        }
    }

    private fun createMissingDestinationDirectories(
        root: String,
        destinationPath: String,
        client: TransferClient,
        authorization: String,
    ) {
        destinationCollectionPaths(destinationPath).forEach { path ->
            client.createCollection(root.childUrl(path), authorization)
        }
    }

    private suspend fun uploadTus(
        transfer: TransferEntity,
        account: AccountEntity,
        collectionUrl: String,
        client: TransferClient,
        source: () -> java.io.InputStream,
    ) {
        check(transfer.allowsUnconditionalReplacement())
        val metadata = "filename ${Base64.getEncoder().encodeToString(transfer.displayName.toByteArray())}"
        var authorization = WorkerAuthorizationProvider(applicationContext).authorization(account)
        val session =
            openTusSession(
                transfer.tusUrl?.let { client.resolveTusLocation(collectionUrl, it) },
                offset = { client.tusOffset(it, authorization) },
                create = {
                    client.createTusUpload(collectionUrl, authorization, transfer.bytesTotal, metadata)
                },
                reset = { checkpoint(transfer, 0, null) },
            )
        val url = session.url
        var offset = session.offset
        if (offset > transfer.bytesTotal) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        checkpoint(transfer, offset, url)
        while (offset < transfer.bytesTotal) {
            authorization = WorkerAuthorizationProvider(applicationContext).authorization(account)
            val remaining = minOf(transfer.bytesTotal - offset, TUS_CHUNK_BYTES)
            val next =
                source().use { input ->
                    input.skipFully(offset)
                    client.patchTus(url, authorization, offset, remaining, { input }) { sent ->
                        updateForegroundProgress(transfer, offset + sent)
                    }
                }
            offset = next
            checkpoint(transfer, offset, url)
        }
    }

    private companion object {
        const val TUS_CHUNK_BYTES = 10L * 1024 * 1024
    }
}

internal fun destinationCollectionPaths(destinationPath: String): List<String> {
    val segments =
        destinationPath
            .trim('/')
            .split('/')
            .filter(String::isNotBlank)
            .dropLast(1)
    return segments.indices.map { index -> "/${segments.take(index + 1).joinToString("/")}" }
}

class DownloadWorker(
    context: Context,
    params: WorkerParameters,
) : TransferWorker(context, params) {
    override val supportsSharedDownloads = true

    override suspend fun executeShared(
        transfer: TransferEntity,
        client: TransferClient,
        authorization: String,
    ) {
        SharedDownloadExecutor.create(applicationContext).execute(
            transfer.id,
            id.toString(),
            client,
            authorization,
        ) { bytes -> updateForegroundProgress(transfer, bytes) }
    }

    override suspend fun execute(
        transfer: TransferEntity,
        account: AccountEntity,
        space: SpaceEntity,
        client: TransferClient,
        authorization: String,
    ) {
        val resourceId = requireNotNull(transfer.resourceId)
        val resource = requireNotNull(store.resource(account.id, space.driveId, resourceId))
        if (resource.path != transfer.destinationPath || resource.sizeBytes != transfer.bytesTotal) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        // A process may stop after publishing the cache but before marking its job complete.
        if (cachedDownload(applicationContext, resource) != null) return
        val expectation = DownloadExpectation(resource.sizeBytes, resource.eTag)
        val cacheDir =
            resourceCacheDirectory(applicationContext.filesDir, account.id, space.driveId).apply {
                mkdirs()
            }
        val target = File(cacheDir, downloadAttemptTargetName(transfer.id))
        val partial = File(cacheDir, "${safePart(transfer.id)}.part")
        val validator = File(cacheDir, "${safePart(transfer.id)}.validator")
        var published = false
        try {
            PrivateCacheUse.hold(listOf(target, partial, validator)) {
                val identity = "${expectation.strongETag}\n${resource.sizeBytes}\n${webDavRoot(
                    space,
                )}\n${resource.path}"
                val offset =
                    prepareDownloadCheckpoint(
                        partial,
                        validator,
                        identity,
                        transfer.bytesTotal,
                        expectation.strongETag != null,
                    )
                if (storage.availableBytes() < (transfer.bytesTotal - offset).coerceAtLeast(0)) {
                    throw OpenCloudException(OpenCloudError.LocalStorage)
                }
                val downloadContext = currentCoroutineContext()
                client.download(
                    webDavRoot(space).childUrl(transfer.destinationPath),
                    authorization,
                    offset,
                    expectation,
                ) { input, _, resumed ->
                    FileOutputStream(partial, resumed).use { output ->
                        val buffer = ByteArray(64 * 1024)
                        var downloaded = if (resumed) offset else 0
                        while (true) {
                            downloadContext.ensureActive()
                            val count = input.read(buffer)
                            if (count < 0) break
                            if (count.toLong() > transfer.bytesTotal - downloaded) {
                                throw OpenCloudException(OpenCloudError.PreconditionFailed)
                            }
                            output.write(buffer, 0, count)
                            downloaded += count
                            updateForegroundProgress(transfer, downloaded)
                        }
                        output.fd.sync()
                    }
                }
                checkpoint(transfer, partial.length())
                require(partial.length() == transfer.bytesTotal) {
                    "The downloaded file size did not match the server metadata."
                }
                verifyCheckpointedDownloadChecksum(
                    client,
                    DownloadChecksumSource(
                        webDavRoot(space).childUrl(transfer.destinationPath),
                        authorization,
                        expectation,
                    ),
                    partial,
                    validator,
                    { downloadContext.ensureActive() },
                )
                require(partial.renameTo(target)) { "The downloaded file could not be published to the local cache." }
                if (!store.publishDownload(transfer, resource, target.absolutePath)) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
                published = true
                validator.delete()
            }
        } finally {
            if (!published) {
                // A Room commit may finish just before cancellation reaches this coroutine. Recheck
                // the DB reference under the cache cleanup gate before removing the renamed target.
                withContext(NonCancellable) {
                    runCatching {
                        cleanupUnpublishedDownloadAttempt(store, transfer, target, partial, validator)
                    }
                }
            }
        }
    }
}

class CacheCleanupWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        val settings =
            SettingsRepository
                .create(applicationContext)
                .settings
                .first()
        val cutoff = System.currentTimeMillis() - settings.cacheRetentionDays * MILLIS_PER_DAY
        withContext(Dispatchers.IO) {
            reclaimExcludedCache(FileBrowserDatabase.create(applicationContext), applicationContext.filesDir)
            expireTemporaryCopies(
                applicationContext,
                FileBrowserStore(FileBrowserDatabase.create(applicationContext)),
                settings.temporaryCopyRetentionHours,
            )
            maintainPrivateCache(
                applicationContext,
                FileBrowserStore(FileBrowserDatabase.create(applicationContext)),
                cutoff,
            )
            SharedDownloadMaintenance(
                FileBrowserDatabase.create(applicationContext),
                applicationContext.filesDir,
            ).expireTemporary(settings.temporaryCopyRetentionHours, System.currentTimeMillis())
        }
        return Result.success()
    }
}

private const val MILLIS_PER_DAY = 24L * 60 * 60 * 1000

private fun String.childUrl(path: String): String =
    toHttpUrl()
        .newBuilder()
        .apply {
            path
                .trim('/')
                .split('/')
                .filter(String::isNotBlank)
                .forEach(::addPathSegment)
        }.build()
        .toString()

private fun java.io.InputStream.skipFully(bytes: Long) {
    var remaining = bytes
    while (remaining > 0) {
        val skipped = skip(remaining)
        if (skipped <= 0) {
            if (read() < 0) error("The upload source changed while resuming.")
            remaining--
        } else {
            remaining -= skipped
        }
    }
}

private fun safePart(value: String): String = cacheIdentity(value)
