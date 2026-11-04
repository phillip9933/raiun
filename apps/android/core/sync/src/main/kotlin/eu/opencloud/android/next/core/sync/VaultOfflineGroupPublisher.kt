package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupPublication
import eu.opencloud.android.next.core.database.VaultGroupPublicationDecision
import eu.opencloud.android.next.core.database.VaultGroupPublicationReservation
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID

/** One verified captured subtree is staged privately, then receives one receipt and one root switch. */
internal class VaultOfflineGroupPublisher(
    private val ownership: VaultOfflineOwnership,
    private val cipherFromMaterial: (ByteArray) -> VaultCipherEngine,
    private val recover: suspend (VaultIdentity, VaultLocation) -> Unit,
    private val beforePublication: () -> Unit,
    private val afterPublication: () -> Unit,
) {
    // One exact group claim and its borrowed key govern the entire atomic publication.
    @Suppress("LongParameterList", "TooGenericExceptionCaught")
    suspend fun publish(
        plan: VaultOfflineGroupVerifiedPlan,
        liveLocation: VaultLocation,
        material: ByteArray,
        expected: VaultGroupLease,
        groups: VaultOfflineGroups,
        livePermit: () -> Boolean,
        publicationAccepted: () -> Unit,
    ) {
        val context = plan.context
        val identity = context.identity
        validateOfflineGroupClaim(plan, expected, liveLocation)
        val grant = VaultOfflineGroupPublicationGrant(identity, currentCoroutineContext(), livePermit)
        val accountGeneration = grant.accountGeneration
        val identityGeneration = grant.identityGeneration
        val checkActive = grant::checkActive
        val permitted = grant::permitted
        ownership.publicationLockFor(identity.accountId).withLock {
            ownership.lockFor(identity).withLock {
                checkActive()
                requireCurrentGroup(groups, expected, context.owner)
                recover(identity, liveLocation)
                requireCurrentGroup(groups, expected, context.owner)
                requireOfflineGroupNotForgotten(ownership, identity)
                val directory = ownership.vaultDirectory(identity)
                val baseBytes = readBase(directory, context.baseOfflineRootDigest)
                val cachedLocation = boundOfflineCatalog(directory, liveLocation, ownership.durability)
                val catalogBytes = readOfflineMetadata(File(directory, "root.json"), 64 * 1024, ownership.durability)
                val checkpoints = offlineGroupCheckpointCommitment(groups, expected, plan.seal, checkActive)
                var reservation: VaultGroupPublicationReservation? = null
                var exact: VaultGroupPublication? = null

                try {
                    val next =
                        prepareNext(plan, liveLocation, cachedLocation, material, directory, checkpoints, checkActive)
                    checkActive()
                    readBase(directory, context.baseOfflineRootDigest).fill(0)
                    beforePublication()
                    val publication = publicationFor(plan, next)
                    exact = publication
                    withContext(NonCancellable) {
                        checkActive()
                        reservation = groups.reservePublication(expected, publication, permitted)
                    }
                    val reserved = requireGroupReservation(reservation)
                    val pending =
                        VaultOfflinePublicationJournal(
                            publication.publicationId,
                            context.groupId,
                            null,
                            encodeLocation(liveLocation).toByteArray(Charsets.UTF_8),
                            baseBytes,
                            catalogBytes,
                            publication.nextRootDigest,
                            groupPublication = publication,
                        )
                    pending.write(directory, ownership.durability)
                    VaultOfflineRevocations.runIfUnchanged(identity, accountGeneration, identityGeneration) {
                        checkActive()
                        ownership.durability.writeAtomic(File(directory, "manifest.enc"), next)
                        ownership.writeCatalog(directory, liveLocation)
                    }
                    withContext(NonCancellable) {
                        afterPublication()
                        checkActive()
                        commitGroup(groups, reserved, permitted)
                        // This callback must only release/invalidate the caller's baseline, never read a root.
                        publicationAccepted()
                        recoverOfflineGroupJournal(ownership, identity, pending, groups)
                    }
                    cleanup(directory, identity, liveLocation, material, checkActive)
                } catch (failure: Throwable) {
                    withContext(NonCancellable) {
                        val resolved = resolveFailure(directory, exact, reservation, context, groups)
                        // A cancelled/locked caller cannot decrypt metadata for GC. A later authorized open can reclaim it.
                        if (resolved && runCatching { permitted() }.getOrDefault(false)) {
                            cleanup(directory, identity, cachedLocation, material, checkActive)
                        }
                    }
                    throw failure
                } finally {
                    baseBytes.fill(0)
                    catalogBytes.fill(0)
                    checkpoints.fill(0)
                }
            }
        }
    }

    @Suppress("LongParameterList") // One generation is bound to its two exact descriptors and borrowed material.
    private fun prepareNext(
        plan: VaultOfflineGroupVerifiedPlan,
        location: VaultLocation,
        cached: VaultLocation,
        material: ByteArray,
        directory: File,
        checkpoints: ByteArray,
        checkActive: () -> Unit,
    ): ByteArray =
        readOfflineManifest(
            File(directory, "manifest.enc"),
            plan.context.identity,
            cached,
            material,
            ownership.durability,
        ).use { base ->
            val replacement = replacementSource(plan, base, location, material, directory, checkpoints)
            VaultOfflineIndex.prepare(
                directory,
                plan.context.identity,
                location,
                material,
                replacement,
                ownership.durability,
                checkActive,
            )
        }

    private fun publicationFor(
        plan: VaultOfflineGroupVerifiedPlan,
        next: ByteArray,
    ): VaultGroupPublication {
        val context = plan.context
        return VaultGroupPublication(
            UUID.randomUUID().toString(),
            context.groupId,
            context.owner,
            context.identityDigest,
            context.descriptorDigest,
            plan.seal.digest,
            plan.seal.memberCount,
            context.baseOfflineRootDigest,
            offlineMetadataDigest(next),
        )
    }

    private fun readBase(
        directory: File,
        expected: String,
    ): ByteArray {
        val file = File(directory, "manifest.enc")
        if (!file.isFile &&
            !File(file.path + ".bak").isFile
        ) {
            throw OpenCloudException(OpenCloudError.OfflineSnapshotChanged)
        }
        val bytes = readOfflineMetadata(file, 16 * 1024 * 1024 + 32, ownership.durability)
        if (offlineMetadataDigest(bytes) != expected) throw OpenCloudException(OpenCloudError.OfflineSnapshotChanged)
        return bytes
    }

    @Suppress("LongParameterList") // Borrowed base and captured plan share one unpublished generation.
    private fun replacementSource(
        plan: VaultOfflineGroupVerifiedPlan,
        base: OfflineManifest,
        location: VaultLocation,
        material: ByteArray,
        directory: File,
        checkpoints: ByteArray,
    ): OfflineManifest {
        val selected = plan.context.selectedEncryptedRoot
        val retained =
            base
                .retaining { entry ->
                    if (!entry.isFolder && selected.startsWith(entry.encryptedPath + "/")) {
                        throw OpenCloudException(OpenCloudError.OfflineSnapshotChanged)
                    }
                    !inside(entry.encryptedPath, selected)
                }.withDirectoryAndAncestors(location, selected.substringBeforeLast('/', location.vaultPath))
        return object : OfflineManifest {
            override fun visit(
                checkActive: () -> Unit,
                consume: (OfflineEntry) -> Unit,
            ) {
                retained.visit(checkActive, consume)
                val actual = VaultOfflineGroupCheckpointCommitment(plan.context.groupId, plan.seal.digest)
                cipherFromMaterial(material).use { cipher ->
                    plan.visitVerified(checkActive) { member ->
                        checkActive()
                        if (member.sequence != actual.count ||
                            !inside(member.source.relativePath, selected)
                        ) {
                            integrity()
                        }
                        if (actual.count == 0L &&
                            (
                                member.kind != VaultOfflineGroupMemberKind.DIRECTORY ||
                                    member.source.relativePath != selected
                            )
                        ) {
                            integrity()
                        }
                        validateDecryptedPath(member, location, cipher)
                        if (member.kind == VaultOfflineGroupMemberKind.FILE) {
                            val job = plan.fileJob(member)
                            if (job.source != member.source ||
                                !job.matchesLocation(location) ||
                                job.rootProofDigest != plan.context.rootProofDigest
                            ) {
                                integrity()
                            }
                            val blob = stageFile(plan.payloadFile(member), member, material, directory, checkActive)
                            actual.append(
                                member.sequence,
                                member.id,
                                member.descriptorDigest,
                                member.kind.name,
                                member.payloadId,
                                blob.size,
                                blob.digest,
                            )
                            consume(blob)
                        } else {
                            actual.append(
                                member.sequence,
                                member.id,
                                member.descriptorDigest,
                                member.kind.name,
                                member.payloadId,
                                0L,
                                null,
                            )
                            if (member.source.relativePath != location.vaultPath) {
                                consume(
                                    OfflineEntry(
                                        member.source.relativePath,
                                        member.source.rawName,
                                        member.source.id,
                                        true,
                                        0L,
                                        member.source.strongETag,
                                        null,
                                        null,
                                    ),
                                )
                            }
                        }
                    }
                }
                val actualDigest = actual.finish(plan.seal)
                try {
                    if (!MessageDigest.isEqual(checkpoints, actualDigest)) integrity()
                } finally {
                    actualDigest.fill(0)
                }
            }
        }
    }

    private fun stageFile(
        payload: File,
        member: VaultOfflineGroupMember,
        material: ByteArray,
        directory: File,
        checkActive: () -> Unit,
    ): OfflineEntry {
        val source = member.source
        if (source.isFolder || source.size < 32) integrity()
        if (!payload.isFile || payload.length() != source.size) integrity()
        val blobs = File(directory, "blobs")
        ownership.durability.requireOwnedDirectory(blobs)
        if (!blobs.mkdirs() && !blobs.isDirectory) throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)
        val stage = File.createTempFile("group-staging-", ".ciphertext", blobs)
        try {
            val digest = copyCiphertext(payload, stage, source.size, checkActive)
            authenticateOfflineCiphertext(stage, material, cipherFromMaterial, checkActive)
            checkActive()
            val id = promoteBlob(stage, blobs)
            return OfflineEntry(
                source.relativePath,
                source.rawName,
                source.id,
                false,
                source.size,
                source.strongETag,
                id,
                digest,
            )
        } finally {
            stage.delete()
        }
    }

    private fun copyCiphertext(
        source: File,
        target: File,
        expected: Long,
        checkActive: () -> Unit,
    ): String {
        val hash = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(64 * 1024)
        var size = 0L
        try {
            FileInputStream(source).use { input ->
                FileOutputStream(target).use { output ->
                    size = copyBytes(input, output, expected, hash, buffer, checkActive)
                    output.fd.sync()
                }
            }
            if (size != expected) integrity()
            return hash.digest().joinToString("") { "%02x".format(it) }
        } finally {
            buffer.fill(0)
        }
    }

    private fun validateDecryptedPath(
        member: VaultOfflineGroupMember,
        location: VaultLocation,
        cipher: VaultCipherEngine,
    ) {
        val source = member.source
        if ((member.kind == VaultOfflineGroupMemberKind.DIRECTORY) != source.isFolder) integrity()
        if (source.relativePath == location.vaultPath) {
            if (!source.isFolder) integrity()
            return
        }
        val prefix =
            location.vaultPath
                .takeIf(String::isNotEmpty)
                ?.plus("/")
                .orEmpty()
        if (!source.relativePath.startsWith(prefix) ||
            source.rawName != source.relativePath.substringAfterLast('/')
        ) {
            integrity()
        }
        val relative = source.relativePath.removePrefix(prefix)
        val plain = cipher.decryptPath(relative)
        if (plain.split('/').any {
                invalidPlainSegment(it)
            }
        ) {
            integrity()
        }
    }

    private fun cleanup(
        directory: File,
        identity: VaultIdentity,
        location: VaultLocation,
        material: ByteArray,
        checkActive: () -> Unit,
    ) {
        if (VaultOfflinePublicationJournal.read(directory) != null) return
        val current = boundOfflineCatalog(directory, location, ownership.durability)
        readOfflineManifest(File(directory, "manifest.enc"), identity, current, material, ownership.durability).use {
            pruneVaultOfflineOrphanBlobs(directory, it, ownership.durability, checkActive)
        }
        val root = readOfflineMetadata(File(directory, "manifest.enc"), 16 * 1024 * 1024 + 32, ownership.durability)
        VaultOfflineIndex.cleanup(directory, listOf(root))
    }

    private fun promoteBlob(
        stage: File,
        blobs: File,
    ): String {
        val id = UUID.randomUUID().toString()
        val target = File(blobs, id)
        if (!target.createNewFile()) storageFailure()
        if (!stage.renameTo(target)) {
            target.delete()
            storageFailure()
        }
        ownership.durability.syncParents(blobs)
        return id
    }

    @Suppress("LongParameterList") // This bounded copy owns its exact length, digest and cancellation guard.
    private fun copyBytes(
        input: FileInputStream,
        output: FileOutputStream,
        expected: Long,
        hash: MessageDigest,
        buffer: ByteArray,
        checkActive: () -> Unit,
    ): Long {
        var size = 0L
        while (true) {
            checkActive()
            val count = input.read(buffer)
            if (count < 0) break
            if (size > expected - count) integrity()
            output.write(buffer, 0, count)
            hash.update(buffer, 0, count)
            size += count
        }
        return size
    }

    private fun invalidPlainSegment(value: String): Boolean =
        value.isBlank() || value in setOf(".", "..") || invalidPlainCharacters(value)

    private fun invalidPlainCharacters(value: String): Boolean = '\\' in value || value.any(Char::isISOControl)

    private suspend fun resolveFailure(
        directory: File,
        exact: VaultGroupPublication?,
        reservation: VaultGroupPublicationReservation?,
        context: VaultOfflineGroupContext,
        groups: VaultOfflineGroups,
    ): Boolean {
        if (reservation == null || exact == null) {
            return groups.isCurrentOwner(context.owner) &&
                offlineMetadataDigest(
                    readOfflineMetadata(
                        File(directory, "manifest.enc"),
                        16 * 1024 * 1024 + 32,
                        ownership.durability,
                    ),
                ) == context.baseOfflineRootDigest
        }
        val pending = VaultOfflinePublicationJournal.read(directory)
        return when {
            pending?.groupPublication == exact -> {
                recoverOfflineGroupJournal(ownership, context.identity, pending, groups)
                true
            }
            pending == null ->
                resolveOfflineGroupWithoutJournal(ownership, context.identity, exact, groups) in
                    setOf(VaultGroupPublicationDecision.ACCEPTED, VaultGroupPublicationDecision.REJECTED)
            else -> false
        }
    }

    private fun storageFailure(): Nothing = throw OpenCloudException(OpenCloudError.LocalStorageWriteFailed)

    private fun inside(
        path: String,
        root: String,
    ): Boolean = root.isEmpty() || path == root || path.startsWith("$root/")

    private fun integrity(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)
}
