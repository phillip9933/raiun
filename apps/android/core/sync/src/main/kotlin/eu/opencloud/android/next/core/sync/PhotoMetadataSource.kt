package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.provider.MediaStore

/** Warning eligibility is broader than the URIs supporting MediaStore.requireOriginal. */
fun isPhotoMetadataSource(
    context: Context,
    uri: Uri,
): Boolean {
    val mimeType =
        try {
            context.contentResolver.getType(uri)
        } catch (_: SecurityException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        }
    return isPhotoMetadataSource(uri, mimeType)
}

internal fun isPhotoMetadataSource(
    uri: Uri,
    mimeType: String?,
): Boolean {
    if (mimeType != null) return mimeType.startsWith("image/", ignoreCase = true)
    return uri.scheme == "content" &&
        when (uri.authority) {
            MediaStore.AUTHORITY -> uri.pathSegments.getOrNull(1) == "images"
            "com.android.providers.media.documents" -> uri.lastPathSegment?.startsWith("image:") == true
            else -> false
        }
}
