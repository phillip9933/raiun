package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import java.io.File
import java.security.MessageDigest

/** Verify the complete private part, including bytes retained from an earlier attempt. */
internal fun verifyDownloadChecksum(
    client: TransferClient,
    source: DownloadChecksumSource,
    partial: File,
    checkActive: () -> Unit,
) {
    checkActive()
    val checksum = client.downloadChecksum(source.url, source.authorization, source.expectation)
    checkActive()
    val (algorithm, expected) = checksum ?: return
    val digest = MessageDigest.getInstance(algorithm)
    var length = 0L
    partial.inputStream().buffered().use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            checkActive()
            val count = input.read(buffer)
            if (count < 0) break
            if (count == 0 || count > source.expectation.length - length) corruptDownload()
            length += count
            digest.update(buffer, 0, count)
        }
    }
    checkActive()
    val actual = digest.digest()
    val expectedBytes = expected.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    if (length != source.expectation.length || !MessageDigest.isEqual(actual, expectedBytes)) corruptDownload()
}

internal fun verifyCheckpointedDownloadChecksum(
    client: TransferClient,
    source: DownloadChecksumSource,
    partial: File,
    validator: File,
    checkActive: () -> Unit,
) {
    try {
        verifyDownloadChecksum(client, source, partial, checkActive)
    } catch (failure: OpenCloudException) {
        if (failure.error == OpenCloudError.PreconditionFailed || failure.error == OpenCloudError.DownloadIntegrity) {
            // Keep network failures resumable; discard bytes only when their version or digest is invalid.
            partial.delete()
            validator.delete()
        }
        throw failure
    }
}

private fun corruptDownload(): Nothing = throw OpenCloudException(OpenCloudError.DownloadIntegrity)
