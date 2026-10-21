package eu.opencloud.android.next.core.sync

import android.content.Context
import android.media.ExifInterface
import android.media.MediaMetadataRetriever
import android.net.Uri
import android.provider.MediaStore
import java.time.Instant
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.Locale

/** Prefer capture dates for media and provider-added dates for other files, then use modified time. */
internal fun backupDateEpochMillis(
    context: Context,
    document: BackupDocument,
): Long {
    val media = document.mimeType.startsWith("image/") || document.mimeType.startsWith("video/")
    val providerDate =
        if (media) {
            queryDate(context, document.uri, MediaStore.Images.ImageColumns.DATE_TAKEN)?.let(::normalizeDateTakenMillis)
        } else {
            queryDate(context, document.uri, MediaStore.MediaColumns.DATE_ADDED)?.let(::normalizeDateAddedSeconds)
        }
    val embeddedDate =
        when {
            document.mimeType.startsWith("image/") -> imageTakenDate(context, document.uri)
            document.mimeType.startsWith("video/") -> videoTakenDate(context, document.uri)
            else -> null
        }
    return (if (media) embeddedDate ?: providerDate else providerDate) ?: document.modified.takeIf { it > 0 } ?: 0
}

private fun queryDate(
    context: Context,
    uri: Uri,
    column: String,
): Long? =
    runCatching {
        context.contentResolver.query(uri, arrayOf(column), null, null, null)?.use { cursor ->
            if (cursor.moveToFirst() && !cursor.isNull(0)) cursor.getLong(0).takeIf { it > 0 } else null
        }
    }.getOrNull()

private fun imageTakenDate(
    context: Context,
    uri: Uri,
): Long? =
    runCatching {
        context.contentResolver.openInputStream(uri)?.use { input ->
            val exif = ExifInterface(input)
            val text =
                exif.getAttribute(ExifInterface.TAG_DATETIME_ORIGINAL)
                    ?: exif.getAttribute(ExifInterface.TAG_DATETIME_DIGITIZED)
            text?.let {
                val local = LocalDateTime.parse(it, DateTimeFormatter.ofPattern("yyyy:MM:dd HH:mm:ss", Locale.US))
                val offset = exif.getAttribute(ExifInterface.TAG_OFFSET_TIME_ORIGINAL)?.let(ZoneOffset::of)
                val instant =
                    if (offset !=
                        null
                    ) {
                        local.atOffset(offset).toInstant()
                    } else {
                        local.atZone(ZoneId.systemDefault()).toInstant()
                    }
                instant.toEpochMilli()
            }
        }
    }.getOrNull()

private fun videoTakenDate(
    context: Context,
    uri: Uri,
): Long? =
    runCatching {
        MediaMetadataRetriever().use { retriever ->
            retriever.setDataSource(context, uri)
            retriever.extractMetadata(MediaMetadataRetriever.METADATA_KEY_DATE)?.let(::parseVideoDate)
        }
    }.getOrNull()

private fun parseVideoDate(value: String): Long? =
    runCatching { Instant.parse(value).toEpochMilli() }.getOrNull()
        ?: runCatching {
            LocalDateTime
                .parse(value, DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss.SSS'Z'", Locale.US))
                .toInstant(ZoneOffset.UTC)
                .toEpochMilli()
        }.getOrNull()

/** MediaStore defines DATE_ADDED in seconds. This is an indexing time, used as a best-effort creation proxy. */
internal fun normalizeDateAddedSeconds(value: Long): Long? =
    if (value > 0) runCatching { Math.multiplyExact(value, 1000L) }.getOrNull() else null

/** MediaStore defines DATE_TAKEN in milliseconds; do not infer units from the timestamp magnitude. */
internal fun normalizeDateTakenMillis(value: Long): Long? = value.takeIf { it > 0 }
