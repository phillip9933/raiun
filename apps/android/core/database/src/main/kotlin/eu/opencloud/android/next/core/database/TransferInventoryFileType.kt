package eu.opencloud.android.next.core.database

/** Mirrors the display contract with Unicode Locale.ROOT lowercasing; SQLite lower() is ASCII-only. */
internal fun inventoryFileType(transfer: TransferEntity): TransferInventoryFileType {
    val mime =
        transfer.mimeType
            ?.substringBefore(';')
            ?.trim()
            ?.lowercase(java.util.Locale.ROOT)
    return when {
        mime?.startsWith("image/") == true -> TransferInventoryFileType.Images
        mime?.startsWith("video/") == true -> TransferInventoryFileType.Videos
        mime?.startsWith("audio/") == true -> TransferInventoryFileType.Audio
        mime?.startsWith("text/") == true || mime in DOCUMENT_MIMES -> TransferInventoryFileType.Documents
        else ->
            when (transfer.displayName.substringAfterLast('.', "").lowercase(java.util.Locale.ROOT)) {
                "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif",
                "bmp", "svg", "tif", "tiff", "raw", "dng",
                ->
                    TransferInventoryFileType.Images
                "mp4", "mov", "mkv", "webm", "avi", "m4v", "3gp", "mpeg", "mpg" -> TransferInventoryFileType.Videos
                "mp3", "m4a", "aac", "wav", "ogg", "flac", "opus", "aiff" -> TransferInventoryFileType.Audio
                "pdf", "txt", "md", "rtf", "csv", "doc", "docx", "xls", "xlsx",
                "ppt", "pptx", "odt", "ods", "odp", "epub",
                ->
                    TransferInventoryFileType.Documents
                else -> TransferInventoryFileType.Other
            }
    }
}

private val DOCUMENT_MIMES =
    setOf(
        "application/pdf",
        "application/rtf",
        "application/epub+zip",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.oasis.opendocument.text",
        "application/vnd.oasis.opendocument.spreadsheet",
        "application/vnd.oasis.opendocument.presentation",
    )
