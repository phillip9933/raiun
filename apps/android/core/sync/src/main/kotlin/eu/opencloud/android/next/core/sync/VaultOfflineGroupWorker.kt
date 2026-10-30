package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.WorkerParameters
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.VAULT_GROUP_LOCATION_KIND
import eu.opencloud.android.next.core.database.VaultGroupAttempt
import eu.opencloud.android.next.core.database.VaultGroupCheckpoint
import eu.opencloud.android.next.core.database.VaultGroupDescriptor
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.database.VaultOfflineGroupEntity
import eu.opencloud.android.next.core.database.VaultOfflineGroupMemberEntity
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.database.vaultOfflineGroups
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
import java.io.FileOutputStream
import kotlin.coroutines.CoroutineContext

/** Fetches only original ciphertext. A complete group still requires a future unlocked publication barrier. */
class VaultOfflineGroupWorker internal constructor(
    context: Context,
    parameters: WorkerParameters,
    private val groups: VaultOfflineGroups,
    private val plans: VaultOfflineGroupPlanStore,
    private val execution: VaultDownloadExecution,
) : CoroutineWorker(context, parameters) {
    constructor(context: Context, parameters: WorkerParameters) : this(
        context,
        parameters,
        FileBrowserStore(FileBrowserDatabase.create(context)).vaultOfflineGroups(),
        VaultOfflineGroupPlanStore(context),
        object : VaultDownloadExecution {
            override fun beginLease(accountId: String) = AccountSessions.get(context).beginLease(accountId)

            override suspend fun download(
                job: VaultDownloadJob,
                payloads: VaultDownloadStore,
                permit: () -> Boolean,
                progress: (Long) -> Unit,
            ): Long = VaultRepository(context).executePreparedDownload(job, payloads, permit, progress)
        },
    )

    override suspend fun doWork(): Result =
        withContext(Dispatchers.IO) {
            val groupId = inputData.getString(TransferWorker.TRANSFER_ID) ?: return@withContext Result.failure()
            val expected = groups.find(groupId) ?: return@withContext Result.success()
            val parent = expected.parent ?: return@withContext Result.success()
            if (parent.locationKind != VAULT_GROUP_LOCATION_KIND ||
                parent.direction != "DOWNLOAD" ||
                !parent.offlinePin
            ) {
                return@withContext Result.failure()
            }
            if (parent.workId != null && parent.workId != id.toString()) return@withContext Result.success()
            if (expected.group.state !in setOf("QUEUED", "RETRY", "RUNNING")) return@withContext Result.success()
            if (parent.notBeforeEpochMillis > System.currentTimeMillis()) return@withContext Result.retry()
            val claimed =
                groups.claim(expected, id.toString(), System.currentTimeMillis())
                    ?: return@withContext Result.success()
            val run = VaultOfflineGroupDownloadRun(groups, plans, execution, claimed, currentCoroutineContext())
            execute(run)
        }

    @Suppress("TooGenericExceptionCaught") // Persist safe transport errors while preserving cancellation.
    private suspend fun execute(run: VaultOfflineGroupDownloadRun): Result =
        try {
            val parent = requireNotNull(run.attempt.lease.parent)
            if (parent.bytesTotal >= TransferNotifications.LARGE_TRANSFER_BYTES) {
                setForeground(
                    TransferNotifications.foregroundInfo(
                        applicationContext,
                        parent.id,
                        applicationContext.getString(R.string.encrypted_offline_download),
                        0,
                        parent.bytesTotal,
                    ),
                )
            }
            run.download()
            Result.success()
        } catch (cancelled: CancellationException) {
            withContext(NonCancellable) {
                groups.deferRetry(run.attempt.lease, "INTERRUPTED", 0, System.currentTimeMillis())
            }
            throw cancelled
        } catch (failure: Exception) {
            val error = failure.toOpenCloudError()
            val parent = requireNotNull(run.attempt.lease.parent)
            val now = System.currentTimeMillis()
            if (error.canRetryTransfer(parent)) {
                val deferred =
                    groups.deferRetry(
                        run.attempt.lease,
                        error.diagnosticCode(),
                        error.retryDeadline(now),
                        now,
                        error.safeMessage(applicationContext),
                    )
                if (deferred == null) Result.success() else Result.retry()
            } else {
                val failed =
                    groups.fail(run.attempt.lease, error.diagnosticCode(), now, error.safeMessage(applicationContext))
                if (failed == null) Result.success() else Result.failure()
            }
        }
}

private class VaultOfflineGroupDownloadRun(
    private val groups: VaultOfflineGroups,
    private val plans: VaultOfflineGroupPlanStore,
    private val execution: VaultDownloadExecution,
    initial: VaultGroupAttempt,
    private val coroutine: CoroutineContext,
) {
    var attempt: VaultGroupAttempt = initial
        private set
    private val owner =
        initial.lease.group.run { VaultGroupOwner(accountId, accountIncarnation, accountIdentityDigest) }
    private val credential by lazy { execution.beginLease(owner.accountId) }
    private var privateAttempt: VaultOfflineGroupPlanStore.Attempt? = null
    private var ownershipCheckedAt: Long? = null
    private var owned = true

    suspend fun download() {
        privateAttempt = plans.beginAttempt(owner, attempt.lease.group.id)
        try {
            plans.open(owner, attempt.lease.group.id).use { plan ->
                requirePlan(plan)
                downloadPlan(plan)
            }
        } finally {
            privateAttempt?.close()
            privateAttempt = null
        }
    }

    private suspend fun downloadPlan(plan: VaultOfflineGroupOpaquePlan) {
        val payloads = plans.payloads(owner, attempt.lease.group.id)
        val counts = DownloadCounts()
        var after: Long? = null
        while (true) {
            requirePermit()
            val page = plan.page(after, 128)
            val rows = groups.memberPage(attempt.lease, after)
            if (page.isEmpty()) {
                if (rows.isNotEmpty()) integrity()
                break
            }
            if (page.size > 128 || rows.size < page.size) integrity()
            consumePage(plan, payloads, page, rows, counts)
            after = page.last().sequence
        }
        if (!counts.matches(plan.seal)) integrity()
        requirePermit(force = true)
        val waiting = groups.awaitUnlock(attempt, System.currentTimeMillis())
        if (waiting == null && groups.isCurrent(attempt.lease)) integrity()
    }

    private suspend fun consumePage(
        plan: VaultOfflineGroupOpaquePlan,
        payloads: VaultDownloadStore,
        page: List<VaultOfflineGroupMember>,
        rows: List<VaultOfflineGroupMemberEntity>,
        counts: DownloadCounts,
    ) {
        for (index in page.indices) {
            requirePermit()
            val member = page[index]
            val row = rows[index]
            if (member.sequence != counts.members || !matches(row, member)) integrity()
            if (member.kind == VaultOfflineGroupMemberKind.FILE) {
                downloadFile(plan, payloads, member, row)
                counts.files = Math.addExact(counts.files, 1)
                counts.bytes = Math.addExact(counts.bytes, member.source.size)
            } else if (row.state != "DOWNLOADED" || row.checkpointBytes != 0L) {
                integrity()
            }
            counts.members = Math.addExact(counts.members, 1)
        }
    }

    private suspend fun downloadFile(
        plan: VaultOfflineGroupOpaquePlan,
        payloads: VaultDownloadStore,
        member: VaultOfflineGroupMember,
        original: VaultOfflineGroupMemberEntity,
    ) {
        val job = plan.fileJob(member)
        if (job.id != original.payloadId || job.source != member.source) integrity()
        val partial = payloads.partial(job)
        if (validCompletedPayload(job, original, partial)) return
        if (original.state == "DOWNLOADED") payloads.discardPayload(job.id)
        val payloadAttempt = payloads.beginAttempt(job.id, owner.accountId)
        try {
            val startBytes = if (partial.isFile) partial.length().coerceIn(0, job.source.size) else 0
            val progress = FileProgress(checkpoint(original, VaultGroupCheckpoint("RUNNING", startBytes)))
            val size =
                execution.download(job, payloads, { payloadAttempt.isActive && permitted() }) {
                    recordProgress(progress, job.source.size, it)
                }
            completePayload(job, partial, size, progress.row, payloadAttempt)
        } finally {
            payloadAttempt.close()
        }
    }

    private fun validCompletedPayload(
        job: VaultDownloadJob,
        row: VaultOfflineGroupMemberEntity,
        partial: java.io.File,
    ): Boolean =
        row.state == "DOWNLOADED" &&
            row.checkpointBytes == job.source.size &&
            partial.isFile &&
            partial.length() == job.source.size &&
            sha256File(partial) { requirePermit() } == row.ciphertextDigest

    private fun recordProgress(
        progress: FileProgress,
        size: Long,
        bytes: Long,
    ) {
        if (bytes !in 0..size) integrity()
        val now = android.os.SystemClock.elapsedRealtime()
        val elapsed = progress.savedAt?.let { now - it }
        val due = elapsed == null || elapsed >= 500 || bytes == size
        if (bytes != progress.row.checkpointBytes && due) {
            progress.row = runBlocking { checkpoint(progress.row, VaultGroupCheckpoint("RUNNING", bytes)) }
            progress.savedAt = now
        }
    }

    private suspend fun completePayload(
        job: VaultDownloadJob,
        partial: java.io.File,
        size: Long,
        row: VaultOfflineGroupMemberEntity,
        payloadAttempt: VaultDownloadStore.Attempt,
    ) {
        requirePermit(force = true)
        val complete = size == job.source.size && partial.isFile && partial.length() == size
        if (!payloadAttempt.isActive || !complete) integrity()
        FileOutputStream(partial, true).use { it.fd.sync() }
        val digest = sha256File(partial) { requirePermit() }
        checkpoint(row, VaultGroupCheckpoint("DOWNLOADED", size, digest))
    }

    private class FileProgress(
        var row: VaultOfflineGroupMemberEntity,
        var savedAt: Long? = null,
    )

    private class DownloadCounts(
        var members: Long = 0,
        var files: Long = 0,
        var bytes: Long = 0,
    ) {
        fun matches(seal: VaultGroupSeal): Boolean =
            members == seal.memberCount && files == seal.fileCount && bytes == seal.ciphertextBytes
    }

    private suspend fun checkpoint(
        row: VaultOfflineGroupMemberEntity,
        value: VaultGroupCheckpoint,
    ): VaultOfflineGroupMemberEntity {
        requirePermit()
        val saved =
            groups.checkpoint(attempt, row, value)
                ?: throw CancellationException("Offline group ownership changed")
        attempt = saved.attempt
        ownershipCheckedAt = null
        return saved.member
    }

    private fun permitted(force: Boolean = false): Boolean {
        coroutine.ensureActive()
        if (!credential() || privateAttempt?.isActive != true) return false
        val now = android.os.SystemClock.elapsedRealtime()
        val elapsed = ownershipCheckedAt?.let { now - it }
        val expired = elapsed == null || elapsed >= 500 || elapsed < 0
        if (force || expired) {
            owned = runBlocking { groups.isCurrent(attempt.lease) }
            ownershipCheckedAt = now
        }
        return owned
    }

    private fun requirePermit(force: Boolean = false) {
        if (!permitted(force)) throw CancellationException("Offline group access ended")
    }

    private fun requirePlan(plan: VaultOfflineGroupOpaquePlan) {
        val group = attempt.lease.group
        val descriptor = plan.context.descriptor()
        if (!matchesDescriptor(group, descriptor) || !matchesSeal(group, plan.seal)) integrity()
        val pathMatches = plan.context.selectedEncryptedRoot == attempt.lease.parent?.destinationPath
        if (plan.context.owner != owner || !pathMatches) integrity()
        requirePermit()
    }
}

private fun matchesDescriptor(
    group: VaultOfflineGroupEntity,
    descriptor: VaultGroupDescriptor,
): Boolean =
    descriptor.groupId == group.id &&
        descriptor.driveId == group.driveId &&
        descriptor.remoteVaultId == group.remoteVaultId &&
        descriptor.identityDigest == group.identityDigest &&
        descriptor.descriptorId == group.descriptorId &&
        descriptor.descriptorDigest == group.descriptorDigest &&
        descriptor.baseOfflineRootDigest == group.baseOfflineRootDigest &&
        descriptor.planId == group.planId

private fun matchesSeal(
    group: VaultOfflineGroupEntity,
    seal: VaultGroupSeal,
): Boolean =
    seal.digest == group.sealedPlanDigest &&
        seal.memberCount == group.sealedMemberCount &&
        seal.fileCount == group.sealedFileCount &&
        seal.ciphertextBytes == group.sealedCiphertextBytes

private fun matches(
    row: VaultOfflineGroupMemberEntity,
    member: VaultOfflineGroupMember,
): Boolean =
    row.sequence == member.sequence &&
        row.memberId == member.id &&
        row.descriptorDigest == member.descriptorDigest &&
        row.kind == member.kind.name &&
        row.payloadId == member.payloadId

private fun integrity(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)
