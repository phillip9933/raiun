package eu.opencloud.android.next.feature.transfers

import androidx.compose.runtime.saveable.listSaver
import eu.opencloud.android.next.core.database.TransferEntity
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneId

internal enum class TransferFileType { ALL, IMAGES, VIDEOS, DOCUMENTS, AUDIO, OTHER }

internal enum class TransferStatusFilter { ALL, ACTIVE, ATTENTION, SUCCEEDED, CANCELLED }

/** Date boundaries are local start dates, including the entire last selected day. */
internal data class TransferFilters(
    val direction: String? = null,
    val fileType: TransferFileType = TransferFileType.ALL,
    val status: TransferStatusFilter = TransferStatusFilter.ALL,
    val startDate: LocalDate? = null,
    val endDate: LocalDate? = null,
) {
    fun matches(
        transfer: TransferEntity,
        zone: ZoneId,
    ): Boolean {
        val matchesDirection = direction == null || transfer.direction == direction
        val matchesType = fileType == TransferFileType.ALL || transferFileType(transfer) == fileType
        val date = Instant.ofEpochMilli(transfer.createdAtEpochMillis).atZone(zone).toLocalDate()
        val matchesDates =
            (startDate == null || !date.isBefore(startDate)) && (endDate == null || !date.isAfter(endDate))
        return matchesDirection && matchesType && matchesStatus(transfer.state) && matchesDates
    }

    private fun matchesStatus(state: String): Boolean =
        when (status) {
            TransferStatusFilter.ALL -> true
            TransferStatusFilter.ACTIVE -> state in setOf("QUEUED", "RUNNING", "RETRY", "AWAITING_UNLOCK")
            TransferStatusFilter.ATTENTION -> state in setOf("FAILED", "CONFLICT")
            TransferStatusFilter.SUCCEEDED -> state == "SUCCEEDED"
            TransferStatusFilter.CANCELLED -> state == "CANCELLED"
        }
}

internal fun TransfersUiState.filtered(
    filters: TransferFilters,
    zone: ZoneId,
): TransfersUiState =
    copy(
        active = active.filter { filters.matches(it, zone) },
        failed = failed.filter { filters.matches(it, zone) },
        history = history.filter { filters.matches(it, zone) },
    )

internal fun transferFileType(transfer: TransferEntity): TransferFileType {
    val mime =
        transfer.mimeType
            ?.substringBefore(';')
            ?.trim()
            ?.lowercase(java.util.Locale.ROOT)
    return when {
        mime?.startsWith("image/") == true -> TransferFileType.IMAGES
        mime?.startsWith("video/") == true -> TransferFileType.VIDEOS
        mime?.startsWith("audio/") == true -> TransferFileType.AUDIO
        mime?.startsWith("text/") == true || mime in DOCUMENT_MIMES -> TransferFileType.DOCUMENTS
        else ->
            when (transfer.displayName.substringAfterLast('.', "").lowercase(java.util.Locale.ROOT)) {
                "jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "avif",
                "bmp", "svg", "tif", "tiff", "raw", "dng",
                -> TransferFileType.IMAGES
                "mp4", "mov", "mkv", "webm", "avi", "m4v", "3gp", "mpeg", "mpg" -> TransferFileType.VIDEOS
                "mp3", "m4a", "aac", "wav", "ogg", "flac", "opus", "aiff" -> TransferFileType.AUDIO
                "pdf", "txt", "md", "rtf", "csv", "doc", "docx", "xls", "xlsx",
                "ppt", "pptx", "odt", "ods", "odp", "epub",
                -> TransferFileType.DOCUMENTS
                else -> TransferFileType.OTHER
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

internal val transferFiltersSaver =
    listSaver<TransferFilters, String>(
        save = {
            listOf(
                it.direction.orEmpty(),
                it.status.name,
                it.fileType.name,
                it.startDate?.toString().orEmpty(),
                it.endDate?.toString().orEmpty(),
            )
        },
        restore = {
            TransferFilters(
                direction = it[0].ifEmpty { null },
                status = TransferStatusFilter.valueOf(it[1]),
                fileType = TransferFileType.valueOf(it[2]),
                startDate = it[3].takeIf(String::isNotEmpty)?.let(LocalDate::parse),
                endDate = it[4].takeIf(String::isNotEmpty)?.let(LocalDate::parse),
            )
        },
    )
