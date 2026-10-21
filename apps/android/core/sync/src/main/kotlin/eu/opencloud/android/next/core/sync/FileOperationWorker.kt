package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.FileOperationEntity
import eu.opencloud.android.next.core.database.FileOperationStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.network.DavOperationClient
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.util.UUID

class FileOperationManager(
    private val context: Context,
) {
    private val database = FileBrowserDatabase.create(context)
    private val store = FileBrowserStore(database)
    private val operations = FileOperationStore(database)

    private companion object {
        val enqueueMutex = Mutex()
    }

    fun observe(accountId: String) = operations.dao.observe(accountId)

    suspend fun retry(
        id: String,
        accountId: String,
    ) {
        operations.dao.retry(id, accountId)
        reconcile()
    }

    suspend fun dismiss(
        id: String,
        accountId: String,
    ) = operations.dismiss(id, accountId)

    // Destination inputs stay explicit; namingBase preserves the original name during conflict retries.
    @Suppress("LongParameterList")
    suspend fun enqueue(
        source: ResourceEntity,
        destinationSpace: String,
        parentId: String?,
        name: String,
        move: Boolean,
        namingBase: String = name,
    ) = withContext(Dispatchers.IO) {
        enqueueMutex.withLock {
            requireOperationName(name)
            requireOperationName(namingBase)
            val from = requireNotNull(store.space(source.accountId, source.spaceId))
            val to = requireNotNull(store.space(source.accountId, destinationSpace))
            val parent = parentId?.let { requireNotNull(store.resource(source.accountId, destinationSpace, it)) }
            require(parent == null || parent.kind == eu.opencloud.android.next.core.model.ResourceKind.FOLDER)
            val parentPath = parent?.path?.trimEnd('/').orEmpty()
            val destinationPath = "$parentPath/$name"
            val sourceUrl = operationUrl(webDavRoot(from), source.path).toHttpUrl()
            val destinationUrl = operationUrl(webDavRoot(to), destinationPath).toHttpUrl()
            require(
                sourceUrl.scheme == destinationUrl.scheme &&
                    sourceUrl.host == destinationUrl.host &&
                    sourceUrl.port == destinationUrl.port,
            ) {
                "This server does not support operations between these storage hosts."
            }
            val account = requireNotNull(store.account(source.accountId))
            val authorization = WorkerAuthorizationProvider(context).authorization(account)
            val client =
                DavOperationClient(TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl))

            suspend fun occupied(path: String): Boolean =
                operations.dao.destinationReserved(source.accountId, destinationSpace, path) != 0 ||
                    client.stat(operationUrl(webDavRoot(to), path), authorization) != null
            if (occupied(destinationPath)) {
                throw FileOperationNameConflictException(
                    availableOperationName(
                        namingBase,
                        source.kind == eu.opencloud.android.next.core.model.ResourceKind.FOLDER,
                        parentPath,
                        ::occupied,
                    ),
                )
            }
            require(
                sourceUrl != destinationUrl &&
                    !destinationUrl.encodedPath.startsWith(sourceUrl.encodedPath.trimEnd('/') + "/"),
            ) {
                "Choose a different destination outside the source folder."
            }
            val eTag =
                DownloadExpectation(source.sizeBytes, source.eTag).strongETag
                    ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            operations.enqueue(
                FileOperationEntity(
                    UUID.randomUUID().toString(),
                    source.accountId,
                    source.spaceId,
                    destinationSpace,
                    source.remoteId,
                    source.parentId,
                    parentId,
                    webDavRoot(from),
                    webDavRoot(to),
                    source.path,
                    destinationPath,
                    eTag,
                    move,
                    source.kind == eu.opencloud.android.next.core.model.ResourceKind.FOLDER,
                ),
            )
            reconcile()
        }
    }

    suspend fun reconcile() {
        var after = ""
        while (true) {
            val page = operations.dao.pending(after)
            if (page.isEmpty()) return
            page.forEach { operation ->
                val request =
                    OneTimeWorkRequestBuilder<FileOperationWorker>()
                        .setInputData(workDataOf("operationId" to operation.id))
                        .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.NOT_REQUIRED).build())
                        .addTag(accountWorkTag(operation.accountId))
                        .build()
                WorkManager
                    .getInstance(
                        context,
                    ).enqueueUniqueWork("file-operation-${operation.id}", ExistingWorkPolicy.KEEP, request)
                    .result
                    .get()
            }
            after = page.last().id
        }
    }
}

internal fun numberedCopyName(
    name: String,
    folder: Boolean,
    number: Int,
): String {
    val dot = if (folder) name.length else name.lastIndexOf('.').takeIf { it > 0 } ?: name.length
    return "${name.substring(0, dot)} ($number)${name.substring(dot)}"
}

class FileOperationWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {
    @Suppress("TooGenericExceptionCaught")
    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val database = FileBrowserDatabase.create(applicationContext)
            val operations = FileOperationStore(database)
            val operationId = inputData.getString("operationId") ?: return@withContext Result.failure()
            val lease = UUID.randomUUID().toString()
            if (operations.dao.claim(operationId, lease) != 1) return@withContext Result.success()
            val operation = operations.dao.find(operationId) ?: return@withContext Result.success()
            try {
                setForeground(
                    TransferNotifications.foregroundInfo(
                        applicationContext,
                        operation.id,
                        operation.sourcePath.substringAfterLast('/'),
                        0,
                        0,
                    ),
                )
                val store = FileBrowserStore(database)
                val account = requireNotNull(store.account(operation.accountId))
                val from = requireNotNull(store.space(operation.accountId, operation.sourceSpaceId))
                val to = requireNotNull(store.space(operation.accountId, operation.destinationSpaceId))
                require(webDavRoot(from) == operation.sourceRoot && webDavRoot(to) == operation.destinationRoot)
                val authorization = WorkerAuthorizationProvider(applicationContext).authorization(account)
                val client =
                    DavOperationClient(TlsPolicy(applicationContext).applyTo(OkHttpClient(), account.serverUrl))
                val coroutine = currentCoroutineContext()
                withRequestCancellation(client::cancelRequests, isOwned = {
                    operations.dao.find(operation.id)?.lease == lease
                }) {
                    executeFileOperation(operation, client, authorization, {
                        coroutine.ensureActive()
                    }, markDeleting = {
                        check(operations.dao.deleting(operation.id, lease) == 1)
                    }) { fingerprint ->
                        check(operations.dao.sent(operation.id, lease, fingerprint) == 1)
                    }
                }
                if (operations.complete(
                        operation,
                        lease,
                    )
                ) {
                    TransferManager(applicationContext, store).reconcileDiscovery()
                    schedulePendingPins(applicationContext)
                }
                Result.success()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                currentCoroutineContext().ensureActive()
                val typed = failure.toOpenCloudError()
                val retry = typed.canRetryFileOperation(runAttemptCount)
                val phase = operations.dao.find(operation.id)?.state ?: return@withContext Result.success()
                operations.dao.finish(operation.id, lease, if (retry) phase else "NEEDS_ATTENTION", typed.safeMessage())
                if (retry) Result.retry() else Result.failure()
            }
        }
}

// Explicit journal callbacks keep the protocol ordering testable.
@Suppress("ThrowsCount", "LongParameterList")
internal suspend fun executeFileOperation(
    operation: FileOperationEntity,
    client: DavOperationClient,
    authorization: String,
    checkActive: () -> Unit,
    markDeleting: suspend () -> Unit = {},
    markSent: suspend (String) -> Unit,
) {
    val source = operationUrl(operation.sourceRoot, operation.sourcePath)
    val destination = operationUrl(operation.destinationRoot, operation.destinationPath)
    var fingerprint = operation.fingerprint
    val crossSpaceFileMove =
        operation.move && operation.sourceSpaceId != operation.destinationSpaceId && !operation.sourceFolder
    if (operation.state !in setOf("SENT", "DELETING")) {
        checkActive()
        fingerprint = prepareOperation(operation, client, authorization, checkActive)
        checkActive()
        markSent(fingerprint)
        client.mutate(source, destination, operation.move && !crossSpaceFileMove, operation.sourceETag, authorization)
    }
    checkActive()
    if (fingerprint == null) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    awaitVerifiedFingerprint(destination, fingerprint, client, authorization, checkActive)
    if (crossSpaceFileMove && client.stat(source, authorization) != null) {
        checkActive()
        markDeleting()
        client.deleteVerifiedSource(source, operation.sourceETag, authorization)
    }
    if (operation.move) awaitSourceRemoval(source, client, authorization, checkActive)
}

private suspend fun awaitVerifiedFingerprint(
    destination: String,
    fingerprint: String,
    client: DavOperationClient,
    authorization: String,
    checkActive: () -> Unit,
) {
    var observedMismatch = false
    for (wait in VERIFICATION_DELAYS_MS) {
        checkActive()
        if (wait > 0) delay(wait)
        try {
            if (client.matchesFingerprint(destination, fingerprint, authorization, checkActive)) return
            observedMismatch = true
        } catch (failure: OpenCloudException) {
            if (!failure.isPostMutationTransient()) throw failure
        }
    }
    throw OpenCloudException(if (observedMismatch) OpenCloudError.PreconditionFailed else OpenCloudError.NotReady(5))
}

private suspend fun awaitSourceRemoval(
    source: String,
    client: DavOperationClient,
    authorization: String,
    checkActive: () -> Unit,
) {
    var transientObserved = false
    for (wait in VERIFICATION_DELAYS_MS) {
        checkActive()
        if (wait > 0) delay(wait)
        try {
            if (client.stat(source, authorization) == null) return
        } catch (failure: OpenCloudException) {
            if (!failure.isPostMutationTransient()) throw failure
            transientObserved = true
        }
    }
    throw OpenCloudException(if (transientObserved) OpenCloudError.NotReady(5) else OpenCloudError.PreconditionFailed)
}

private fun OpenCloudException.isPostMutationTransient(): Boolean =
    error == OpenCloudError.NotFound ||
        error == OpenCloudError.InvalidResponse ||
        error == OpenCloudError.PreconditionFailed ||
        error is OpenCloudError.NotReady ||
        ((error as? OpenCloudError.ServerFailure)?.statusCode in setOf(500, 502, 503, 504))

private fun OpenCloudError.canRetryFileOperation(attempt: Int): Boolean =
    attempt < 5 &&
        (
            this in setOf(OpenCloudError.Connectivity, OpenCloudError.Timeout) ||
                this is OpenCloudError.NotReady ||
                this is OpenCloudError.ServerFailure &&
                statusCode in setOf(500, 502, 503, 504)
        )

private val VERIFICATION_DELAYS_MS = longArrayOf(0, 150, 300, 600, 1_200, 2_400)

private fun prepareOperation(
    operation: FileOperationEntity,
    client: DavOperationClient,
    authorization: String,
    checkActive: () -> Unit,
): String {
    val source = operationUrl(operation.sourceRoot, operation.sourcePath)
    val destination = operationUrl(operation.destinationRoot, operation.destinationPath)
    val before = client.stat(source, authorization) ?: throw OpenCloudException(OpenCloudError.NotFound)
    requireOperation(before.eTag == operation.sourceETag && before.folder == operation.sourceFolder)
    if (client.stat(destination, authorization) != null) throw OpenCloudException(OpenCloudError.Conflict)
    val fingerprint = client.verificationFingerprint(source, authorization, checkActive)
    requireOperation(client.stat(source, authorization)?.eTag == operation.sourceETag)
    return fingerprint
}

private fun requireOperation(valid: Boolean) {
    if (!valid) throw OpenCloudException(OpenCloudError.PreconditionFailed)
}

private fun operationUrl(
    root: String,
    path: String,
): String =
    root
        .toHttpUrl()
        .newBuilder()
        .apply {
            path.trim('/').split('/').filter(String::isNotEmpty).forEach { segment ->
                require(segment !in setOf(".", ".."))
                addPathSegment(segment)
            }
        }.build()
        .toString()

/** A known destination collision is resolved before any operation is journaled or sent. */
class FileOperationNameConflictException(
    val suggestedName: String,
) : Exception("A destination item already exists.")

internal suspend fun availableOperationName(
    baseName: String,
    folder: Boolean,
    parentPath: String,
    occupied: suspend (String) -> Boolean,
): String {
    for (number in 1..10000) {
        val candidate = numberedCopyName(baseName, folder, number)
        if (!occupied("$parentPath/$candidate")) return candidate
    }
    throw OpenCloudException(OpenCloudError.Conflict)
}

private fun requireOperationName(name: String) {
    require(
        name.isNotBlank() &&
            name !in setOf(".", "..") &&
            name.none { it == '/' || it == '\\' || it.isISOControl() },
    )
}
