package eu.opencloud.android.next.core.model

import android.webkit.MimeTypeMap
import java.util.Locale

/** Use the same type for ACTION_VIEW and the granted document URI. */
fun fileMimeType(
    name: String,
    reported: String?,
): String {
    val extension = name.substringAfterLast('.', "").lowercase(Locale.ROOT)
    if (extension == "apk") return "application/vnd.android.package-archive"
    val declared = reported?.substringBefore(';')?.trim()?.lowercase(Locale.ROOT)
    return declared?.takeIf { it.contains('/') && it !in setOf("application/octet-stream", "binary/octet-stream") }
        ?: MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension)
        ?: "application/octet-stream"
}
