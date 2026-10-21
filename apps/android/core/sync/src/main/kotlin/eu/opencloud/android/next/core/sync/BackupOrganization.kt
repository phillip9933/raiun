package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FolderBackupEntity
import java.time.Instant
import java.time.ZoneId
import java.time.format.TextStyle
import java.util.Locale

private val dateToken = Regex("\\[([A-Za-z]+)]")
private val supportedDateTokens = setOf("YYYY", "YY", "MMMM", "MMM", "MM", "M", "DD", "D")

/** Formats a user supplied date path safely. Invalid templates return null. */
@Suppress("CyclomaticComplexMethod", "ComplexCondition", "ReturnCount")
fun formatBackupDateFolder(
    template: String,
    epochMillis: Long,
    zone: ZoneId = ZoneId.systemDefault(),
): String? {
    if (epochMillis <= 0 || template.isBlank() || template.length > 128) return null
    val components = template.split('/')
    if (components.size > 16 ||
        components.any { it.isEmpty() || it.length > 64 || it == "." || it == ".." }
    ) {
        return null
    }
    if (components.any { component -> component.any { !(it.isLetterOrDigit() || it in " ._-[]") } }) return null
    val tokens = dateToken.findAll(template).toList()
    if (tokens.isEmpty() || tokens.any { it.groupValues[1] !in supportedDateTokens }) return null
    val withoutTokens = dateToken.replace(template, "")
    if ('[' in withoutTokens || ']' in withoutTokens) return null
    val date = Instant.ofEpochMilli(epochMillis).atZone(zone)
    val replacements =
        mapOf(
            "YYYY" to date.year.toString().padStart(4, '0'),
            "YY" to (date.year % 100).toString().padStart(2, '0'),
            "MMMM" to date.month.getDisplayName(TextStyle.FULL, Locale.ENGLISH),
            "MMM" to date.month.getDisplayName(TextStyle.SHORT, Locale.ENGLISH),
            "MM" to date.monthValue.toString().padStart(2, '0'),
            "M" to date.monthValue.toString(),
            "DD" to date.dayOfMonth.toString().padStart(2, '0'),
            "D" to date.dayOfMonth.toString(),
        )
    val output = dateToken.replace(template) { match -> replacements.getValue(match.groupValues[1]) }
    if (output.length > 512 ||
        output.split('/').any { it.isEmpty() || it == "." || it == ".." || it.length > 255 }
    ) {
        return null
    }
    return output
}

fun isValidBackupDateTemplate(template: String): Boolean = formatBackupDateFolder(template, 1_790_687_999_000L) != null

internal fun backupDestination(
    backup: FolderBackupEntity,
    document: BackupDocument,
    dateEpochMillis: Long = document.modified,
): String {
    val template =
        when (backup.dateOrganization) {
            "NONE" -> ""
            "YEAR_MONTH" -> "[YYYY]/[MM]"
            else -> backup.dateOrganization
        }
    val dateFolder = if (template.isEmpty()) "" else formatBackupDateFolder(template, dateEpochMillis) ?: "Undated"
    return backupParent(backupParent(backup.destinationPath, dateFolder), document.relativeParent)
}

internal fun backupReceiptKey(
    backup: FolderBackupEntity,
    document: BackupDocument,
): String {
    val binding =
        if (backup.destinationRevision == 0L) {
            emptyList()
        } else {
            listOf(
                "destination-revision:${backup.destinationRevision}",
                backup.accountId,
                backup.destinationKind,
                backup.spaceId,
                backup.sharedShareId.orEmpty(),
                backup.sharedFolderId.orEmpty(),
            )
        }
    return (
        binding +
            listOf(
                backup.destinationPath,
                backup.dateOrganization,
                document.relativeParent,
                document.name,
                document.uri.toString(),
            )
    ).joinToString("\u0000")
}
