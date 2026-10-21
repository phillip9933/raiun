package eu.opencloud.android.next.core.sync

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.AssetFileDescriptor
import android.net.Uri
import android.os.Build
import android.os.CancellationSignal
import android.provider.MediaStore
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.IOException
import java.io.InputStream

fun isSystemMediaSource(uri: Uri): Boolean =
    uri.scheme == "content" &&
        uri.authority in
        setOf(
            MediaStore.AUTHORITY,
            "com.android.providers.media.documents",
            "com.android.externalstorage.documents",
        )

/** True only for image collection URIs where the app can request MediaStore's original bytes. */
fun isEligibleOriginalMediaSource(
    context: Context,
    uri: Uri,
): Boolean =
    when {
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q || uri.scheme != "content" -> false
        uri.authority == MediaStore.AUTHORITY -> isMediaCollectionItem(uri) && isImage(context, uri)
        // Keep the picker-granted document URI as the selected source. MediaDocumentsProvider
        // chooses the representation it exposes; converting it to MediaStore would change the
        // URI and cannot guarantee original, unredacted bytes.
        uri.authority == "com.android.providers.media.documents" -> false
        else -> false
    }

private fun isImage(
    context: Context,
    uri: Uri,
): Boolean =
    if (uri.pathSegments.getOrNull(1) == "images") {
        true
    } else {
        try {
            context.contentResolver.getType(uri)?.startsWith("image/", ignoreCase = true) == true
        } catch (_: SecurityException) {
            false
        } catch (_: IllegalArgumentException) {
            false
        }
    }

private fun isMediaCollectionItem(uri: Uri): Boolean {
    val parts = uri.pathSegments
    return (
        parts.size == 4 &&
            parts[1] == "images" &&
            parts[2] == "media" ||
            parts.size == 3 &&
            parts[1] == "file"
    ) &&
        parts.last().toLongOrNull() != null
}

/** True when the upload source will request MediaStore's unredacted media representation. */
internal fun requestsOriginalMedia(
    context: Context,
    uri: Uri,
): Boolean =
    Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
        isEligibleOriginalMediaSource(context, uri) &&
        context.checkSelfPermission(Manifest.permission.ACCESS_MEDIA_LOCATION) == PackageManager.PERMISSION_GRANTED

/** Provider metadata can describe the redacted representation while reads return the original. */
internal fun uploadStagingExpectedLength(
    context: Context,
    uri: Uri,
    declaredLength: Long,
): Long = if (requestsOriginalMedia(context, uri)) -1 else declaredLength

/** Request original bytes only for eligible MediaStore images; never retry a failed original read. */
fun openUploadSource(
    context: Context,
    uri: Uri,
): InputStream {
    val original =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && requestsOriginalMedia(context, uri)) {
            MediaStore.setRequireOriginal(uri)
        } else {
            uri
        }
    return context.contentResolver.openInputStream(original)
        ?: throw OpenCloudException(OpenCloudError.SourceUnavailable)
}

/** Incoming shares use a provider cancellation signal so a dismissed share can stop a blocked open. */
internal fun openIncomingUploadSource(
    context: Context,
    uri: Uri,
    signal: CancellationSignal,
    isStopped: () -> Boolean,
    pollReady: (StructPollfd, Int) -> Boolean = { descriptor, timeout -> Os.poll(arrayOf(descriptor), timeout) > 0 },
): InputStream {
    val source =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && requestsOriginalMedia(context, uri)) {
            MediaStore.setRequireOriginal(uri)
        } else {
            uri
        }
    val descriptor =
        context.contentResolver.openAssetFileDescriptor(source, "r", signal)
            ?: throw OpenCloudException(OpenCloudError.SourceUnavailable)
    return cancellableAssetInputStream(descriptor, signal, isStopped, pollReady)
}

/** Polling avoids a blocked pipe read that Android does not release when its descriptor is closed. */
@Suppress("NestedBlockDepth")
internal fun cancellableAssetInputStream(
    descriptor: AssetFileDescriptor,
    signal: CancellationSignal,
    isStopped: () -> Boolean,
    pollReady: (StructPollfd, Int) -> Boolean = { candidate, timeout -> Os.poll(arrayOf(candidate), timeout) > 0 },
): InputStream =
    object : InputStream() {
        private val content = descriptor.createInputStream()
        private var remaining = descriptor.length
        private val pollfd =
            StructPollfd().apply {
                fd = descriptor.parcelFileDescriptor.fileDescriptor
                events = (OsConstants.POLLIN or OsConstants.POLLHUP or OsConstants.POLLERR).toShort()
            }

        override fun read(): Int {
            if (remaining == 0L) return -1
            awaitReadable()
            return content.read().also { if (it >= 0 && remaining > 0) remaining-- }
        }

        @Suppress("ReturnCount") // Zero-length reads and the declared asset end complete without polling.
        override fun read(
            bytes: ByteArray,
            offset: Int,
            length: Int,
        ): Int {
            if (offset < 0 || length < 0 || offset > bytes.size - length) {
                throw IndexOutOfBoundsException("Invalid shared-source buffer range")
            }
            if (length == 0) return 0
            if (remaining == 0L) return -1
            awaitReadable()
            val limit = if (remaining > 0) minOf(length.toLong(), remaining).toInt() else length
            return content.read(bytes, offset, limit).also { if (it > 0 && remaining > 0) remaining -= it }
        }

        override fun close() = content.close()

        @Suppress("ThrowsCount") // Cancellation and descriptor failures must end the read before publication.
        private fun awaitReadable() {
            while (true) {
                if (isStopped() || signal.isCanceled) throw IOException("Incoming share stopped")
                try {
                    if (pollReady(pollfd, 250)) {
                        if (isStopped() || signal.isCanceled) throw IOException("Incoming share stopped")
                        return
                    }
                } catch (failure: ErrnoException) {
                    if (isStopped() || signal.isCanceled) throw IOException("Incoming share stopped")
                    throw IOException("Could not read the shared source", failure)
                }
            }
        }
    }
