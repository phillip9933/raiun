package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.security.MessageDigest
import java.util.Base64

internal fun uploadSourceFiles(directory: File): List<File> =
    listOf("partial", "payload", "seal").map { File(directory, it) }

/** Copies provider bytes unchanged. Once sealed, retries use this immutable local source. */
internal fun stageUploadSource(
    directory: File,
    expectedLength: Long,
    source: () -> InputStream,
    available: () -> Long,
    checkActive: () -> Unit,
): File =
    stageUploadSource(directory, expectedLength, source, available, 1024L * 1024, Long.MAX_VALUE, {
    }, {}, checkActive)

/** The intake variant reserves room for the upload queue's second copy and guards provider reads. */
@Suppress("ThrowsCount", "LongParameterList")
internal fun stageUploadSource(
    directory: File,
    expectedLength: Long,
    source: () -> InputStream,
    available: () -> Long,
    minimumFreeBytes: Long,
    maximumBytes: Long,
    onReadStart: () -> Unit,
    onReadEnd: () -> Unit,
    checkActive: () -> Unit,
): File {
    directory.mkdirs()
    val payload = File(directory, "payload")
    val seal = File(directory, "seal")
    if (payload.isFile && seal.isFile) {
        if (seal.length() > 128 || seal.readText() != sourceSeal(payload, checkActive)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        return payload
    }
    val partial = File(directory, "partial")
    source().use { input ->
        FileOutputStream(partial).use { output ->
            copySourceBytes(
                input,
                output,
                expectedLength,
                available,
                checkActive,
                minimumFreeBytes,
                maximumBytes,
                onReadStart,
                onReadEnd,
            )
            checkActive()
            output.fd.sync()
        }
    }
    checkActive()
    if (payload.exists() && !payload.delete()) throw OpenCloudException(OpenCloudError.LocalStorage)
    if (!partial.renameTo(payload)) throw OpenCloudException(OpenCloudError.LocalStorage)
    checkActive()
    FileOutputStream(seal).use { output ->
        output.write(sourceSeal(payload, checkActive).toByteArray())
        output.fd.sync()
    }
    checkActive()
    return payload
}

@Suppress("ThrowsCount", "LongParameterList") // Streaming validates content and invokes intake-specific guards.
private fun copySourceBytes(
    input: InputStream,
    output: FileOutputStream,
    expectedLength: Long,
    available: () -> Long,
    checkActive: () -> Unit,
    minimumFreeBytes: Long,
    maximumBytes: Long,
    onReadStart: () -> Unit,
    onReadEnd: () -> Unit,
) {
    var total = 0L
    val buffer = ByteArray(64 * 1024)
    while (true) {
        checkActive()
        onReadStart()
        val read =
            try {
                input.read(buffer)
            } finally {
                onReadEnd()
            }
        checkActive()
        if (read < 0) break
        if (read > maximumBytes - total) throw OpenCloudException(OpenCloudError.LocalStorage)
        if (read == 0 || (expectedLength >= 0 && read > expectedLength - total)) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
        if (available() < read + minimumFreeBytes) throw OpenCloudException(OpenCloudError.LocalStorage)
        output.write(buffer, 0, read)
        total += read
    }
    if (expectedLength >= 0 &&
        total != expectedLength
    ) {
        throw OpenCloudException(OpenCloudError.PreconditionFailed)
    }
}

private fun sourceSeal(
    file: File,
    checkActive: () -> Unit,
): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(64 * 1024)
        while (true) {
            checkActive()
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return "${file.length()}:${Base64.getEncoder().encodeToString(digest.digest())}"
}
