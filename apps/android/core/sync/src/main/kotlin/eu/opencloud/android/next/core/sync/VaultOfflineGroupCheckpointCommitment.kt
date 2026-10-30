package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.nio.ByteBuffer
import java.security.MessageDigest

/** Two ordered, framed streams bind untrusted download hints to the actual authenticated staged bytes. */
internal class VaultOfflineGroupCheckpointCommitment(
    groupId: String,
    planDigest: String,
) {
    private val hash = MessageDigest.getInstance("SHA-256")
    var count = 0L
        private set
    private var files = 0L
    private var bytes = 0L

    init {
        text("RAIUN-GROUP-CHECKPOINT-1")
        text(groupId)
        text(planDigest)
    }

    @Suppress("LongParameterList") // Exact sealed membership and actual transport checkpoint form one framed record.
    fun append(
        sequence: Long,
        memberId: String,
        descriptorDigest: String,
        kind: String,
        payloadId: String?,
        checkpointBytes: Long,
        ciphertextDigest: String?,
    ) {
        if (sequence != count) integrity()
        when (kind) {
            "DIRECTORY" -> if (payloadId != null || checkpointBytes != 0L || ciphertextDigest != null) integrity()
            "FILE" -> {
                if (payloadId == null || checkpointBytes < 32 || ciphertextDigest?.matches(DIGEST) != true) integrity()
                files = Math.addExact(files, 1L)
                bytes = Math.addExact(bytes, checkpointBytes)
            }
            else -> integrity()
        }
        long(sequence)
        text(memberId)
        text(descriptorDigest)
        text(kind)
        nullableText(payloadId)
        text("DOWNLOADED")
        long(checkpointBytes)
        nullableText(ciphertextDigest)
        count = Math.addExact(count, 1L)
    }

    fun finish(seal: VaultGroupSeal): ByteArray {
        if (count != seal.memberCount || files != seal.fileCount || bytes != seal.ciphertextBytes) integrity()
        text("END")
        long(count)
        long(files)
        long(bytes)
        return hash.digest()
    }

    private fun long(value: Long) {
        hash.update(ByteBuffer.allocate(8).putLong(value).array())
    }

    private fun nullableText(value: String?) {
        hash.update(if (value == null) 0.toByte() else 1.toByte())
        value?.let(::text)
    }

    private fun text(value: String) {
        val encoded = value.toByteArray(Charsets.UTF_8)
        hash.update(ByteBuffer.allocate(4).putInt(encoded.size).array())
        hash.update(encoded)
    }

    private fun integrity(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)

    private companion object {
        val DIGEST = Regex("[a-f0-9]{64}")
    }
}

internal suspend fun offlineGroupCheckpointCommitment(
    groups: VaultOfflineGroups,
    expected: VaultGroupLease,
    seal: VaultGroupSeal,
    checkActive: () -> Unit,
): ByteArray {
    val summary = VaultOfflineGroupCheckpointCommitment(expected.group.id, seal.digest)
    var after: Long? = null
    while (true) {
        checkActive()
        val page = groups.memberPage(expected, after)
        if (page.isEmpty()) break
        page.forEach { row ->
            checkActive()
            if (row.groupId != expected.group.id || row.state != "DOWNLOADED") {
                throw OpenCloudException(OpenCloudError.DownloadIntegrity)
            }
            summary.append(
                row.sequence,
                row.memberId,
                row.descriptorDigest,
                row.kind,
                row.payloadId,
                row.checkpointBytes,
                row.ciphertextDigest,
            )
        }
        after = page.last().sequence
    }
    checkActive()
    if (!groups.isCurrent(expected)) throw OpenCloudException(OpenCloudError.SourceChanged)
    return summary.finish(seal)
}
