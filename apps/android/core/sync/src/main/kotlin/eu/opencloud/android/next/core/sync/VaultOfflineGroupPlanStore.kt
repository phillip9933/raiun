package eu.opencloud.android.next.core.sync

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Original opaque descriptors and ciphertext only. Ordinary download reconciliation cannot enter this root. */
@Suppress("LargeClass") // One owner coordinates plan preparation, authenticated readers and keyless attempts.
internal class VaultOfflineGroupPlanStore(
    private val root: File,
    private val durability: OfflineDurability = OfflineDurability(root),
) {
    constructor(context: Context) : this(
        File(context.noBackupFilesDir, "vault-offline-group-jobs"),
        OfflineDurability(context.noBackupFilesDir),
    )

    fun hasActivePreparation(
        owner: VaultGroupOwner,
        groupId: String,
    ): Boolean {
        if (ownerRevoked(owner)) return false
        val path = directory(owner, groupId).canonicalPath
        return synchronized(uses) { uses[path]?.let { it.preparing && it.owner == owner } == true }
    }

    @Suppress("TooGenericExceptionCaught") // Failed creation must remove only its owned preparation.
    fun begin(
        context: VaultOfflineGroupContext,
        checkActive: () -> Unit = {},
    ): Preparation {
        VaultOfflineGroupPlanCodec.context(context)
        val directory = directory(context.owner, context.groupId)
        return using(directory) { state ->
            synchronized(state) {
                requireOwner(context.owner)
                checkActive()
                check(!directory.exists() && isIdle(state))
                check(directory.mkdirs())
                state.owner = context.owner
                state.preparing = true
                state.references.incrementAndGet()
                try {
                    durability.writeAtomic(file(directory, "context"), VaultOfflineGroupPlanCodec.context(context))
                    Preparation(context, directory, state, checkActive)
                } catch (failure: Throwable) {
                    state.preparing = false
                    state.references.decrementAndGet()
                    state.deleteWhenIdle = true
                    cleanupIdle(directory, state)
                    throw failure
                }
            }
        }
    }

    fun open(
        owner: VaultGroupOwner,
        groupId: String,
    ): VaultOfflineGroupOpaquePlan {
        val directory = directory(owner, groupId)
        return using(directory) { state ->
            synchronized(state) {
                requireOwner(owner)
                val context = boundContext(owner, groupId, directory)
                val sealed = readOfflineMetadata(file(directory, "seal"), 88)
                val seal = VaultOfflineGroupPlanCodec.sealInfo(context, sealed)
                state.readers++
                state.references.incrementAndGet()
                Opaque(context, directory, state, state.epoch.get(), sealed, seal)
            }
        }
    }

    fun payloads(
        owner: VaultGroupOwner,
        groupId: String,
    ): VaultDownloadStore {
        requireOwner(owner)
        val directory = directory(owner, groupId)
        check(directory.isDirectory)
        boundContext(owner, groupId, directory)
        return VaultDownloadStore(
            durability.requireOwnedDirectory(File(directory, "downloads")),
            registryNamespace = directory.canonicalPath,
        )
    }

    fun beginAttempt(
        owner: VaultGroupOwner,
        groupId: String,
    ): Attempt {
        val directory = directory(owner, groupId)
        return using(directory) { state ->
            synchronized(state) {
                requireOwner(owner)
                boundContext(owner, groupId, directory)
                check(file(directory, "seal").isFile)
                if (state.attempts.isNotEmpty()) throw OpenCloudException(OpenCloudError.NotReady(1))
                Attempt(owner, directory, state, state.epoch.get()).also {
                    state.attempts.add(it)
                    state.references.incrementAndGet()
                }
            }
        }
    }

    /** Durable cancellation must happen first. Live attempts/readers close before their bytes are removed. */
    fun cancel(
        owner: VaultGroupOwner,
        groupId: String,
        discardPayloads: Boolean = false,
    ) {
        val directory = directory(owner, groupId)
        if (!directory.exists()) return
        boundContext(owner, groupId, directory)
        using(directory) { state ->
            state.epoch.incrementAndGet()
            synchronized(state) {
                state.discardWhenIdle = state.discardWhenIdle || discardPayloads
                cleanupIdle(directory, state)
            }
        }
    }

    fun reconcile(
        owner: VaultGroupOwner,
        retained: (String) -> Boolean,
    ) {
        val directory = ownerDirectory(owner)
        if (!directory.isDirectory) return
        Files.newDirectoryStream(directory.toPath()).use { groups ->
            for (path in groups) {
                val id = path.fileName.toString()
                if (runCatching { VaultOfflineGroupPlanCodec.uuid(id) }.isFailure) continue
                val group = directory(owner, id)
                using(group) { state ->
                    synchronized(state) {
                        if (isIdle(state) &&
                            runCatching { boundContext(owner, id, group) }.isSuccess &&
                            !retained(id)
                        ) {
                            state.deleteWhenIdle = true
                            cleanupIdle(group, state)
                        }
                    }
                }
            }
        }
    }

    /** Exact incarnation only; never delegates to the account-ID-only ordinary payload forget operation. */
    fun forget(owner: VaultGroupOwner) {
        revokedOwners.add(ownerKey(owner))
        val directory = ownerDirectory(owner)
        if (!directory.isDirectory) return
        Files.newDirectoryStream(directory.toPath()).use { groups ->
            for (path in groups) {
                val group = ownedGroup(owner, path.fileName.toString()) ?: continue
                using(group) { state ->
                    state.epoch.incrementAndGet()
                    synchronized(state) {
                        state.deleteWhenIdle = true
                        cleanupIdle(group, state)
                    }
                }
            }
        }
    }

    inner class Preparation internal constructor(
        val context: VaultOfflineGroupContext,
        private val directory: File,
        private val state: Use,
        private val checkActive: () -> Unit,
    ) : AutoCloseable {
        private val epoch = state.epoch.get()
        private val records = VaultOfflineGroupPlanDatabase(file(directory, "plan.db"))
        private var database: SQLiteDatabase? = records.create()
        private val pending = ArrayList<VaultOfflineGroupPlanRecord>(MAX_PENDING_RECORDS)
        private var pendingBytes = 0
        private var count = 0L
        private var files = 0L
        private var bytes = 0L
        private val hash = MessageDigest.getInstance("SHA-256")
        private var sealed = false
        private var frozen = false
        private var finished = false

        fun appendDirectory(source: VaultDavEntry): VaultOfflineGroupMember =
            synchronized(state) {
                require(source.isFolder)
                append(source, null, null)
            }

        fun appendFile(source: VaultDavEntry): VaultOfflineGroupMember =
            synchronized(state) {
                require(!source.isFolder)
                active()
                val payloads = payloads(context.owner, context.groupId)
                val job = payloads.create(context.location, source, context.rootProofDigest)
                var keep = false
                try {
                    val readback = payloads.read(job.id)
                    if (readback != job) VaultOfflineGroupPlanCodec.integrity()
                    durability.syncParents(requireNotNull(payloads.partial(job).parentFile))
                    append(source, job.id, VaultOfflineGroupPlanCodec.jobDigest(job)).also { keep = true }
                } finally {
                    payloads.finishPrepared(job.id) { keep }
                }
            }

        private fun append(
            source: VaultDavEntry,
            payload: String?,
            payloadDigest: String?,
        ): VaultOfflineGroupMember {
            active()
            check(!frozen)
            val member = VaultOfflineGroupPlanCodec.createMember(context, count, source, payload, payloadDigest)
            val encoded = VaultOfflineGroupPlanCodec.member(member)
            val nextCount = Math.addExact(count, 1L)
            val nextFiles = if (source.isFolder) files else Math.addExact(files, 1L)
            val nextBytes = if (source.isFolder) bytes else Math.addExact(bytes, source.size)
            records.validateAppend(requireNotNull(database), member, pending)
            if (pending.isNotEmpty() && encoded.size > MAX_RECORD - pendingBytes) flushPending()
            pending.add(VaultOfflineGroupPlanRecord(member, encoded))
            pendingBytes += encoded.size
            VaultOfflineGroupPlanCodec.update(hash, count, encoded)
            count = nextCount
            files = nextFiles
            bytes = nextBytes
            if (pending.size == MAX_PENDING_RECORDS || pendingBytes == MAX_RECORD) flushPending()
            return member
        }

        /** Plan records must be durable before their corresponding Room membership is admitted. */
        fun flush() =
            synchronized(state) {
                active()
                check(!frozen)
                flushPending()
            }

        // A failed batch has uncertain write state and must never be retried or sealed.
        @Suppress("TooGenericExceptionCaught")
        private fun flushPending() {
            if (pending.isEmpty()) return
            try {
                records.appendBatch(requireNotNull(database), pending) { active() }
                active()
                pending.clear()
                pendingBytes = 0
            } catch (failure: Throwable) {
                frozen = true
                throw failure
            }
        }

        fun seal(
            material: ByteArray,
            checkActive: () -> Unit = {},
        ): VaultGroupSeal =
            synchronized(state) {
                active()
                check(!frozen && count > 0)
                flushPending()
                frozen = true
                val writer = requireNotNull(database)
                database = null
                records.closeWriter(writer)
                FileOutputStream(file(directory, "plan.db"), true).use { it.fd.sync() }
                durability.syncParents(directory)
                val expected = hash.digest()
                val summary =
                    records.scan(context, {
                        active()
                        checkActive()
                    }) { member -> readJob(context, member) }
                if (!summary.matchesCounts(count, files, bytes) ||
                    !MessageDigest.isEqual(summary.digest, expected)
                ) {
                    VaultOfflineGroupPlanCodec.integrity()
                }
                val root =
                    VaultOfflineGroupPlanCodec.seal(
                        context,
                        longArrayOf(count, files, bytes),
                        expected,
                        material,
                    )
                durability.writeAtomic(file(directory, "seal"), root)
                active()
                checkActive()
                sealed = true
                VaultOfflineGroupPlanCodec.sealInfo(context, root)
            }

        /** Call in NonCancellable after the Room seal transaction, including interrupted result delivery. */
        fun finishPrepared(retain: () -> Boolean): Boolean =
            synchronized(state) {
                check(!finished)
                val keep = sealed && !ownerRevoked(context.owner) && state.epoch.get() == epoch && retain()
                releasePreparation(delete = !keep)
                keep
            }

        override fun close() =
            synchronized(state) {
                if (!finished) {
                    // A sealed plan may already have crossed an interrupted durable admission. Reconcile decides.
                    releasePreparation(delete = !sealed)
                }
            }

        private fun releasePreparation(delete: Boolean) {
            finished = true
            val writer = database
            database = null
            pending.clear()
            pendingBytes = 0
            try {
                writer?.let { records.closeWriter(it) }
            } finally {
                state.preparing = false
                state.references.decrementAndGet()
                state.deleteWhenIdle = state.deleteWhenIdle || delete
                finishUse(directory, state)
            }
        }

        private fun active() {
            check(!finished)
            requireLive(context.owner, state, epoch)
            checkActive()
        }
    }

    inner class Attempt internal constructor(
        private val owner: VaultGroupOwner,
        private val directory: File,
        private val state: Use,
        private val epoch: Long,
    ) : AutoCloseable {
        @Volatile private var closed = false
        val isActive: Boolean get() = !closed && !ownerRevoked(owner) && state.epoch.get() == epoch

        override fun close() =
            synchronized(state) {
                if (!closed) {
                    closed = true
                    state.attempts.remove(this)
                    state.references.decrementAndGet()
                    finishUse(directory, state)
                }
            }
    }

    private inner class Opaque(
        override val context: VaultOfflineGroupContext,
        private val directory: File,
        private val state: Use,
        private val epoch: Long,
        private val rootBytes: ByteArray,
        override val seal: VaultGroupSeal,
    ) : VaultOfflineGroupOpaquePlan {
        private var closed = false

        override fun page(
            afterSequence: Long?,
            limit: Int,
        ): List<VaultOfflineGroupMember> =
            synchronized(state) {
                live()
                require(afterSequence == null || afterSequence < seal.memberCount)
                val page = database(directory).page(context, afterSequence, limit)
                var next = Math.addExact(afterSequence ?: -1L, 1L)
                page.forEach {
                    if (it.sequence != next++ ||
                        it.sequence >= seal.memberCount
                    ) {
                        VaultOfflineGroupPlanCodec.integrity()
                    }
                }
                if (page.isEmpty() && next < seal.memberCount) VaultOfflineGroupPlanCodec.integrity()
                page
            }

        override fun fileJob(member: VaultOfflineGroupMember): VaultDownloadJob =
            synchronized(state) {
                live()
                boundJob(context, directory, member)
            }

        override fun verify(
            material: ByteArray,
            expectedContext: VaultOfflineGroupContext,
            checkActive: () -> Unit,
        ): VaultOfflineGroupVerifiedPlan =
            synchronized(state) {
                live()
                if (context != expectedContext) VaultOfflineGroupPlanCodec.integrity()
                VerifiedPlan.authenticate(
                    this@VaultOfflineGroupPlanStore,
                    context,
                    directory,
                    state,
                    epoch,
                    rootBytes,
                    seal,
                    material,
                    checkActive,
                )
            }

        override fun close() =
            synchronized(state) {
                if (!closed) {
                    closed = true
                    state.readers--
                    state.references.decrementAndGet()
                    finishUse(directory, state)
                }
            }

        private fun live() {
            check(!closed)
            requireLive(context.owner, state, epoch)
        }
    }

    @Suppress("LongParameterList") // Exact owner/context/seal/key and lifetime bindings form one verified lease.
    class VerifiedPlan private constructor(
        private val store: VaultOfflineGroupPlanStore,
        val context: VaultOfflineGroupContext,
        private val directory: File,
        private val state: Use,
        private val epoch: Long,
        private val rootBytes: ByteArray,
        val seal: VaultGroupSeal,
        private val material: ByteArray,
    ) : AutoCloseable {
        private var closed = false
        private var visiting = false
        private var currentAuthenticatedMember: VaultOfflineGroupMember? = null

        fun visitVerified(
            checkActive: () -> Unit = {},
            consume: (VaultOfflineGroupMember) -> Unit,
        ) = synchronized(state) {
            live()
            if (visiting) VaultOfflineGroupPlanCodec.integrity()
            visiting = true
            try {
                store.verifyRecords(context, directory, rootBytes, seal, material, {
                    live()
                    checkActive()
                }) { member ->
                    deliverAuthenticatedMember(member, consume)
                }
            } finally {
                currentAuthenticatedMember = null
                visiting = false
            }
        }

        private fun deliverAuthenticatedMember(
            member: VaultOfflineGroupMember,
            consume: (VaultOfflineGroupMember) -> Unit,
        ) {
            currentAuthenticatedMember = member
            try {
                consume(member)
            } finally {
                currentAuthenticatedMember = null
            }
        }

        fun fileJob(member: VaultOfflineGroupMember): VaultDownloadJob =
            synchronized(state) {
                live()
                if (visiting) {
                    if (currentAuthenticatedMember != member) VaultOfflineGroupPlanCodec.integrity()
                    store.readJob(context, member) ?: VaultOfflineGroupPlanCodec.integrity()
                } else {
                    store.boundJob(context, directory, member)
                }
            }

        fun payloadFile(member: VaultOfflineGroupMember): File =
            synchronized(state) {
                val job = fileJob(member)
                store.payloads(context.owner, context.groupId).partial(job)
            }

        override fun close() =
            synchronized(state) {
                if (!closed) {
                    closed = true
                    material.fill(0)
                    state.readers--
                    state.references.decrementAndGet()
                    store.finishUse(directory, state)
                }
            }

        private fun live() {
            check(!closed)
            store.requireLive(context.owner, state, epoch)
        }

        companion object {
            @Suppress("LongParameterList") // Construction is gated by complete authenticated persisted membership.
            internal fun authenticate(
                store: VaultOfflineGroupPlanStore,
                context: VaultOfflineGroupContext,
                directory: File,
                state: Use,
                epoch: Long,
                root: ByteArray,
                seal: VaultGroupSeal,
                material: ByteArray,
                checkActive: () -> Unit,
            ): VerifiedPlan =
                synchronized(state) {
                    check(directory == store.directory(context.owner, context.groupId))
                    check(synchronized(uses) { uses[directory.canonicalPath] === state })
                    store.requireLive(context.owner, state, epoch)
                    if (VaultOfflineGroupPlanCodec.sealInfo(context, root) !=
                        seal
                    ) {
                        VaultOfflineGroupPlanCodec.integrity()
                    }
                    store.verifyRecords(context, directory, root, seal, material, {
                        store.requireLive(context.owner, state, epoch)
                        checkActive()
                    }) {}
                    state.readers++
                    state.references.incrementAndGet()
                    VerifiedPlan(store, context, directory, state, epoch, root.copyOf(), seal, material.copyOf())
                }
        }
    }

    @Suppress("LongParameterList") // Verification retains every immutable authority and its final publication barrier.
    private fun verifyRecords(
        context: VaultOfflineGroupContext,
        directory: File,
        root: ByteArray,
        seal: VaultGroupSeal,
        material: ByteArray,
        active: () -> Unit,
        consume: (VaultOfflineGroupMember) -> Unit,
    ) {
        if (boundContext(context.owner, context.groupId, directory) != context) VaultOfflineGroupPlanCodec.integrity()
        if (!MessageDigest.isEqual(
                root,
                readOfflineMetadata(file(directory, "seal"), 88),
            )
        ) {
            VaultOfflineGroupPlanCodec.integrity()
        }
        val digest = VaultOfflineGroupPlanCodec.authenticateSeal(context, root, material)
        try {
            database(directory).verifiedVisit(context, active, { readJob(context, it) }, { summary ->
                if (!summary.matchesCounts(seal.memberCount, seal.fileCount, seal.ciphertextBytes) ||
                    !MessageDigest.isEqual(digest, summary.digest)
                ) {
                    VaultOfflineGroupPlanCodec.integrity()
                }
            }, consume)
            if (boundContext(context.owner, context.groupId, directory) !=
                context
            ) {
                VaultOfflineGroupPlanCodec.integrity()
            }
            active()
        } finally {
            digest.fill(0)
        }
    }

    private fun readJob(
        context: VaultOfflineGroupContext,
        member: VaultOfflineGroupMember,
    ): VaultDownloadJob? {
        VaultOfflineGroupPlanCodec.validateMember(context, member)
        if (member.kind == VaultOfflineGroupMemberKind.DIRECTORY) return null
        val job = payloads(context.owner, context.groupId).read(requireNotNull(member.payloadId))
        if (!matchesCapturedJob(context, member, job)) VaultOfflineGroupPlanCodec.integrity()
        return job
    }

    private fun matchesCapturedJob(
        context: VaultOfflineGroupContext,
        member: VaultOfflineGroupMember,
        job: VaultDownloadJob,
    ): Boolean {
        val sameSource = job.matchesLocation(context.location) && job.source == member.source
        val sameProof =
            job.rootProofDigest == context.rootProofDigest &&
                VaultOfflineGroupPlanCodec.jobDigest(job) == member.payloadDescriptorDigest
        return sameSource && sameProof
    }

    private fun boundJob(
        context: VaultOfflineGroupContext,
        directory: File,
        member: VaultOfflineGroupMember,
    ): VaultDownloadJob {
        require(member.sequence >= 0)
        val actual = database(directory).page(context, member.sequence - 1L, 1).singleOrNull()
        if (actual != member) VaultOfflineGroupPlanCodec.integrity()
        return readJob(context, member) ?: VaultOfflineGroupPlanCodec.integrity()
    }

    private fun database(directory: File) = VaultOfflineGroupPlanDatabase(file(directory, "plan.db"))

    private fun boundContext(
        owner: VaultGroupOwner,
        id: String,
        directory: File,
    ): VaultOfflineGroupContext {
        val context =
            VaultOfflineGroupPlanCodec.readContext(
                readOfflineMetadata(file(directory, "context"), MAX_RECORD),
            )
        if (context.owner != owner || context.groupId != id) VaultOfflineGroupPlanCodec.integrity()
        return context
    }

    private fun directory(
        owner: VaultGroupOwner,
        id: String,
    ): File {
        VaultOfflineGroupPlanCodec.uuid(id)
        return durability.requireOwnedDirectory(File(ownerDirectory(owner), id))
    }

    private fun ownerDirectory(owner: VaultGroupOwner): File {
        VaultOfflineGroupPlanCodec.incarnation(owner.incarnation)
        VaultOfflineGroupPlanCodec.hash(owner.accountIdentityDigest)
        val account =
            durability.requireOwnedDirectory(
                File(root, VaultOfflineGroupPlanCodec.digest(owner.accountId.toByteArray())),
            )
        return durability.requireOwnedDirectory(File(account, owner.incarnation))
    }

    private fun file(
        directory: File,
        name: String,
    ): File {
        durability.requireOwnedDirectory(directory)
        val file = File(directory, name)
        listOf("", ".bak", ".new", "-journal", "-wal", "-shm").forEach {
            check(!Files.isSymbolicLink(File(file.path + it).toPath()))
        }
        return file
    }

    private fun requireOwner(owner: VaultGroupOwner) {
        if (ownerRevoked(owner)) throw OpenCloudException(OpenCloudError.AccessDenied)
    }

    private fun ownerRevoked(owner: VaultGroupOwner) = ownerKey(owner) in revokedOwners

    private fun ownerKey(owner: VaultGroupOwner) =
        root.canonicalPath + "/" + owner.accountId + "/" + owner.incarnation + "/" + owner.accountIdentityDigest

    private fun requireLive(
        owner: VaultGroupOwner,
        state: Use,
        epoch: Long,
    ) {
        requireOwner(owner)
        if (state.epoch.get() != epoch) throw OpenCloudException(OpenCloudError.AccessDenied)
    }

    private fun cleanupIdle(
        directory: File,
        state: Use,
    ) {
        if (!isIdle(state)) return
        if (state.discardWhenIdle || state.deleteWhenIdle) {
            cleanupPayloads(directory, state.deleteWhenIdle)
            state.discardWhenIdle = false
        }
        if (state.deleteWhenIdle) {
            deleteOwned(directory)
            state.deleteWhenIdle = false
        }
    }

    private fun isIdle(state: Use): Boolean = !state.preparing && state.readers == 0 && state.attempts.isEmpty()

    private fun ownedGroup(
        owner: VaultGroupOwner,
        id: String,
    ): File? {
        if (runCatching { VaultOfflineGroupPlanCodec.uuid(id) }.isFailure) return null
        val group = directory(owner, id)
        return group.takeIf { runCatching { boundContext(owner, id, group) }.isSuccess }
    }

    private fun cleanupPayloads(
        directory: File,
        delete: Boolean,
    ) {
        val downloads = durability.requireOwnedDirectory(File(directory, "downloads"))
        if (!downloads.isDirectory) return
        Files.newDirectoryStream(downloads.toPath()).use { children ->
            val payloads = VaultDownloadStore(downloads)
            for (child in children) {
                val id = child.fileName.toString()
                if (runCatching { VaultOfflineGroupPlanCodec.uuid(id) }.isFailure) continue
                cleanupPayload(payloads, id, delete)
            }
        }
    }

    private fun cleanupPayload(
        payloads: VaultDownloadStore,
        id: String,
        delete: Boolean,
    ) {
        if (delete) payloads.delete(id) else payloads.discardPayload(id)
    }

    private fun finishUse(
        directory: File,
        state: Use,
    ) {
        try {
            cleanupIdle(directory, state)
        } finally {
            releaseInactive(state)
        }
    }

    private fun deleteOwned(directory: File) {
        val canonical = durability.requireOwnedDirectory(directory)
        check(canonical.toPath().startsWith(root.canonicalFile.toPath()) && canonical != root.canonicalFile)

        fun remove(path: java.nio.file.Path) {
            if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.newDirectoryStream(path).use { children ->
                    for (child in children) remove(child)
                }
            }
            Files.deleteIfExists(path)
        }
        remove(canonical.toPath())
        durability.syncParents(requireNotNull(canonical.parentFile))
    }

    private fun <T> using(
        directory: File,
        action: (Use) -> T,
    ): T {
        val path = directory.canonicalPath
        val state = synchronized(uses) { uses.getOrPut(path) { Use(path) }.also { it.borrowers++ } }
        return try {
            action(state)
        } finally {
            synchronized(uses) {
                state.borrowers--
                if (state.borrowers == 0 && state.references.get() == 0) uses.remove(path, state)
            }
        }
    }

    private fun releaseInactive(state: Use) =
        synchronized(uses) {
            if (state.borrowers == 0 && state.references.get() == 0) uses.remove(state.path, state)
            Unit
        }

    internal class Use(
        val path: String,
    ) {
        val epoch = AtomicLong()
        val references = AtomicInteger()
        var borrowers = 0

        @Volatile var preparing = false

        @Volatile var owner: VaultGroupOwner? = null
        var readers = 0
        val attempts = mutableSetOf<Attempt>()
        var deleteWhenIdle = false
        var discardWhenIdle = false
    }

    private companion object {
        const val MAX_RECORD = VaultOfflineGroupPlanCodec.MAX_RECORD_BYTES
        const val MAX_PENDING_RECORDS = 128
        val uses = mutableMapOf<String, Use>()
        val revokedOwners = ConcurrentHashMap.newKeySet<String>()
    }
}
