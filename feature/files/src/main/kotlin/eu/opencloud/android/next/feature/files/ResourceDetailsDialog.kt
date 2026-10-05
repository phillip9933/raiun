package eu.opencloud.android.next.feature.files

import android.content.Context
import android.media.ExifInterface
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.ui.ResourceMetadataDetails
import eu.opencloud.android.next.core.ui.browserDisplayName
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.text.DateFormat
import java.util.Date

@Composable
internal fun ResourceDetailsDialog(
    resource: ResourceEntity,
    options: ResourceDetailsOptions,
    onDismiss: () -> Unit,
    prepareFile: (suspend (ResourceEntity) -> ResourceEntity)? = null,
) {
    var showVersions by remember(resource) { mutableStateOf(false) }
    if (showVersions) {
        FileVersionHistoryDialog(resource, onDismiss = onDismiss)
    } else {
        ResourceDetailsContent(resource, options, onDismiss, prepareFile) {
            showVersions =
                true
        }
    }
}

@Suppress("LongParameterList") // Existing details callbacks plus version-history navigation.
@Composable
private fun ResourceDetailsContent(
    resource: ResourceEntity,
    options: ResourceDetailsOptions,
    onDismiss: () -> Unit,
    prepareFile: (suspend (ResourceEntity) -> ResourceEntity)?,
    onVersions: () -> Unit,
) {
    val keptOffline = options.keptOffline
    val retentionHours = options.retentionHours
    val display = options.display
    val context = LocalContext.current
    var current by remember(resource) { mutableStateOf(resource) }
    var metadata by remember(resource) { mutableStateOf<List<String>>(emptyList()) }
    var localStatus by remember(resource) {
        mutableStateOf(context.localizedString(R.string.file_details_checking_copy))
    }
    var locallyAvailable by remember(resource) { mutableStateOf(false) }
    var loading by remember(resource) { mutableStateOf(false) }
    var error by remember(resource) { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    LaunchedEffect(current, keptOffline, retentionHours) {
        withContext(Dispatchers.IO) {
            val file = detailsCachedFile(context, current)
            locallyAvailable = file != null
            localStatus =
                localCopyDescription(file, keptOffline, retentionHours) { id, args ->
                    localizedFileDetail(context, id, args)
                }
            metadata =
                if (current.isImagePreview() && file != null) {
                    eu.opencloud.android.next.core.sync.LocalCopyLease
                        .read(file) {
                            readPhotoMetadata(file) { id, args -> localizedFileDetail(context, id, args) }
                        }
                } else {
                    emptyList()
                }
        }
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                browserDisplayName(
                    resource.name,
                    resource.kind == eu.opencloud.android.next.core.model.ResourceKind.FOLDER,
                    display,
                ),
            )
        },
        text = {
            Column(
                Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                BasicResourceDetails(resource, display)
                eu.opencloud.android.next.core.ui.ItemActivitiesAction(
                    resource.accountId,
                    resource.remoteId,
                    resource.name,
                )
                if (resource.kind == eu.opencloud.android.next.core.model.ResourceKind.FILE) {
                    FilledTonalButton(onClick = onVersions) { Text(stringResource(R.string.file_versions_title)) }
                }
                Text(localStatus)
                if (resource.isImagePreview()) {
                    HorizontalDivider()
                    Card {
                        Column(
                            modifier = Modifier.padding(OpenCloudDimensions.SpacingMd),
                            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
                        ) {
                            Text(
                                stringResource(R.string.file_details_photo_metadata),
                                style = MaterialTheme.typography.titleSmall,
                            )
                            metadata.forEach { value ->
                                Text(value)
                            }
                            if (locallyAvailable && metadata.isEmpty()) {
                                Text(stringResource(R.string.file_details_no_photo_metadata))
                            }
                            if (!locallyAvailable && prepareFile != null) {
                                FilledTonalButton(enabled = !loading, onClick = {
                                    loading = true
                                    error = null
                                    scope.launch {
                                        try {
                                            current = prepareFile(current)
                                        } catch (cancelled: CancellationException) {
                                            throw cancelled
                                        } catch (_: Exception) {
                                            error =
                                                context.localizedString(R.string.file_details_download_error)
                                        } finally {
                                            loading = false
                                        }
                                    }
                                }) {
                                    Text(
                                        stringResource(
                                            if (loading) {
                                                R.string.file_details_downloading_photo
                                            } else {
                                                R.string.file_details_download_photo
                                            },
                                        ),
                                    )
                                }
                            }
                            error?.let { Text(it) }
                        }
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.file_details_close)) }
        },
    )
}

private fun detailsCachedFile(
    context: Context,
    resource: ResourceEntity,
): File? =
    validatedCachedFile(
        resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
        resource.localPath,
        resource.sizeBytes,
    )

private fun localizedFileDetail(
    context: Context,
    id: Int,
    args: Array<out Any>,
): String =
    when (args.size) {
        0 -> context.localizedString(id)
        1 -> context.localizedString(id, args[0])
        2 -> context.localizedString(id, args[0], args[1])
        else -> error("Unsupported file-details argument count")
    }

internal fun localCopyDescription(
    file: File?,
    keptOffline: Boolean,
    hours: Int,
    now: Long = System.currentTimeMillis(),
    format: (Int, Array<out Any>) -> String = ::englishFileDetails,
): String {
    val deadline = file?.lastModified()?.plus(hours * 3_600_000L)
    return when {
        keptOffline ->
            if (file ==
                null
            ) {
                format(R.string.file_details_kept_pending, emptyArray())
            } else {
                format(R.string.file_details_kept_retained, emptyArray())
            }
        file == null -> format(R.string.file_details_cloud_only, emptyArray())
        hours == 0 -> format(R.string.file_details_temporary_never, emptyArray())
        else -> {
            val timing =
                if (requireNotNull(deadline) <=
                    now
                ) {
                    format(R.string.file_details_now, emptyArray())
                } else {
                    format(
                        R.string.file_details_after_date,
                        arrayOf(DateFormat.getDateTimeInstance().format(Date(deadline))),
                    )
                }
            format(R.string.file_details_temporary_cleanup, arrayOf(timing))
        }
    }
}

// English fallback keeps the helper's existing deterministic unit-test behavior.
private fun englishFileDetails(
    id: Int,
    args: Array<out Any>,
): String {
    val template =
        when (id) {
            R.string.file_details_kept_pending -> "Kept offline: download pending"
            R.string.file_details_kept_retained -> "Kept offline: retained until you remove it"
            R.string.file_details_cloud_only -> "Cloud only"
            R.string.file_details_temporary_never ->
                "Temporary local copy: automatic cleanup is set to Never"
            R.string.file_details_now -> "now"
            R.string.file_details_after_date -> "after %1\$s"
            R.string.file_details_temporary_cleanup ->
                "Temporary local copy: eligible for cleanup %1\$s. Opening it resets this timer. " +
                    "Android may run cleanup later."
            else -> ""
        }
    return formatEnglishTemplate(template, args)
}

// English fallback preserves the existing helper contract for tests and non-UI callers.
internal fun readPhotoMetadata(file: File): List<String> = readPhotoMetadata(file, ::englishPhotoMetadata)

private fun readPhotoMetadata(
    file: File,
    format: (Int, Array<out Any>) -> String,
): List<String> =
    try {
        val exif = ExifInterface(file.absolutePath)
        val fields =
            listOf(
                R.string.file_details_exif_taken to ExifInterface.TAG_DATETIME_ORIGINAL,
                R.string.file_details_exif_make to ExifInterface.TAG_MAKE,
                R.string.file_details_exif_model to ExifInterface.TAG_MODEL,
                R.string.file_details_exif_width to ExifInterface.TAG_IMAGE_WIDTH,
                R.string.file_details_exif_height to ExifInterface.TAG_IMAGE_LENGTH,
                R.string.file_details_exif_exposure to ExifInterface.TAG_EXPOSURE_TIME,
                R.string.file_details_exif_aperture to ExifInterface.TAG_F_NUMBER,
                R.string.file_details_exif_iso to ExifInterface.TAG_ISO_SPEED_RATINGS,
                R.string.file_details_exif_focal_length to ExifInterface.TAG_FOCAL_LENGTH,
            )
        fields.mapNotNull { (labelId, tag) ->
            exif.getAttribute(tag)?.takeIf { it.isNotBlank() }?.let {
                format(R.string.file_details_exif_value, arrayOf(format(labelId, emptyArray()), it))
            }
        } +
            FloatArray(2).let { position ->
                if (exif.getLatLong(position)) {
                    listOf(
                        format(
                            R.string.file_details_exif_gps,
                            arrayOf(position[0].toString(), position[1].toString()),
                        ),
                    )
                } else {
                    emptyList()
                }
            }
    } catch (_: IOException) {
        emptyList()
    }

private fun englishPhotoMetadata(
    id: Int,
    args: Array<out Any>,
): String {
    val template =
        when (id) {
            R.string.file_details_exif_taken -> "Taken"
            R.string.file_details_exif_make -> "Camera make"
            R.string.file_details_exif_model -> "Camera model"
            R.string.file_details_exif_width -> "Width"
            R.string.file_details_exif_height -> "Height"
            R.string.file_details_exif_exposure -> "Exposure (seconds)"
            R.string.file_details_exif_aperture -> "Aperture"
            R.string.file_details_exif_iso -> "ISO"
            R.string.file_details_exif_focal_length -> "Focal length"
            R.string.file_details_exif_value -> "%1\$s: %2\$s"
            R.string.file_details_exif_gps -> "GPS: %1\$s, %2\$s"
            else -> ""
        }
    return formatEnglishTemplate(template, args)
}

private fun formatEnglishTemplate(
    template: String,
    args: Array<out Any>,
): String =
    when (args.size) {
        0 -> template
        1 -> template.format(args[0])
        2 -> template.format(args[0], args[1])
        else -> error("Unsupported file-details argument count")
    }

@Composable
private fun BasicResourceDetails(
    resource: ResourceEntity,
    display: FileDisplayOptions,
) {
    val context = LocalContext.current
    val modified =
        resource.modifiedAtEpochMillis.takeIf { display.showModified && it > 0 }?.let {
            DateFormat.getDateTimeInstance().format(Date(it))
        }
    ResourceMetadataDetails(
        location = stringResource(R.string.file_details_location, resource.path),
        type = stringResource(R.string.file_details_type, resource.mimeType ?: resource.kind.name.lowercase()),
        size =
            if (display.showSize) {
                stringResource(
                    R.string.file_details_size,
                    android.text.format.Formatter
                        .formatShortFileSize(context, resource.sizeBytes),
                )
            } else {
                null
            },
        modified = modified?.let { stringResource(R.string.file_details_modified, it) },
    )
}
