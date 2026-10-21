package eu.opencloud.android.next.core.datastore

import java.util.Locale

enum class PreviewKind { TEXT, PDF, IMAGE }

data class FileOpening(
    val externalText: Boolean = false,
    val externalPdf: Boolean = false,
    val externalImages: Boolean = false,
) {
    fun usesPreview(kind: PreviewKind?): Boolean =
        when (kind) {
            PreviewKind.TEXT -> !externalText
            PreviewKind.PDF -> !externalPdf
            PreviewKind.IMAGE -> !externalImages
            null -> false
        }
}

fun previewKind(
    name: String,
    mimeType: String?,
): PreviewKind? {
    val mime = mimeType.orEmpty().substringBefore(';').lowercase(Locale.ROOT)
    val extension = name.substringAfterLast('.', "").lowercase(Locale.ROOT)
    return when {
        mime == "application/pdf" || extension == "pdf" -> PreviewKind.PDF
        mime.startsWith(
            "image/",
        ) ||
            extension in setOf("jpg", "jpeg", "png", "webp", "gif", "bmp", "heic", "heif") -> PreviewKind.IMAGE
        mime.startsWith("text/") ||
            mime in setOf("application/json", "application/xml") ||
            extension in
            setOf(
                "txt",
                "md",
                "markdown",
                "json",
                "xml",
                "yaml",
                "yml",
                "csv",
                "log",
                "ini",
                "conf",
            )
        -> PreviewKind.TEXT
        else -> null
    }
}
