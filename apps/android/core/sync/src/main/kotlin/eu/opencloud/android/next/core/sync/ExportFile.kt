package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.network.ContentFingerprint
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** A move may remove app cache only after the destination has been closed and read back successfully. */
suspend fun exportCachedFile(
    context: Context,
    resource: ResourceEntity,
    destination: Uri,
) {
    require(destination.scheme == "content" && destination.authority != "${context.packageName}.documents") {
        "Choose a destination outside Raiun."
    }
    val source =
        requireNotNull(
            validatedCachedFile(
                resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
                resource.localPath?.takeIf { resource.hasLocalCopy },
                resource.sizeBytes,
            ),
        ) { "The downloaded copy is unavailable." }
    LocalCopyLease.read(source) {
        val coroutine = currentCoroutineContext()
        val expected =
            source.inputStream().use {
                ContentFingerprint.read(
                    it,
                    resource.sizeBytes,
                ) { coroutine.ensureActive() }
            }
        requireNotNull(context.contentResolver.openOutputStream(destination, "wt")).use { output ->
            source.inputStream().use { input ->
                copyExportBytes(input, output) { coroutine.ensureActive() }
            }
        }
        val actual =
            requireNotNull(context.contentResolver.openInputStream(destination)).use {
                ContentFingerprint.read(it, resource.sizeBytes) { coroutine.ensureActive() }
            }
        check(expected.matches(actual)) { "The exported copy could not be verified." }
    }
}

private fun copyExportBytes(
    input: java.io.InputStream,
    output: java.io.OutputStream,
    checkActive: () -> Unit,
) {
    val buffer = ByteArray(64 * 1024)
    while (true) {
        checkActive()
        val read = input.read(buffer)
        if (read < 0) break
        output.write(buffer, 0, read)
    }
}
