package eu.opencloud.android.next.feature.transfers

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.DateRangePicker
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDateRangePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

@OptIn(ExperimentalLayoutApi::class)
@Composable
internal fun TransferFilterControls(
    filters: TransferFilters,
    onChange: (TransferFilters) -> Unit,
) {
    Column(Modifier.padding(horizontal = OpenCloudDimensions.SpacingMd)) {
        FlowRow(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
            TransferDirectionChips(filters, onChange)
            TransferFilterMenu(
                selected = filters.fileType != TransferFileType.ALL,
                label = fileTypeLabel(filters.fileType),
                options = TransferFileType.entries,
                optionLabel = ::fileTypeLabel,
                onSelect = { onChange(filters.copy(fileType = it)) },
            )
            TransferFilterMenu(
                selected = filters.status != TransferStatusFilter.ALL,
                label = statusFilterLabel(filters.status),
                options = TransferStatusFilter.entries,
                optionLabel = ::statusFilterLabel,
                onSelect = { onChange(filters.copy(status = it)) },
            )
            TransferDateFilter(filters, onChange)
            if (filters != TransferFilters()) {
                TextButton(onClick = { onChange(TransferFilters()) }) {
                    Text(stringResource(R.string.transfers_filter_reset))
                }
            }
        }
        if (filters.startDate != null) {
            Text(stringResource(R.string.transfers_filter_started_hint), style = MaterialTheme.typography.bodySmall)
        }
    }
}

@Composable
private fun TransferDirectionChips(
    filters: TransferFilters,
    onChange: (TransferFilters) -> Unit,
) {
    listOf(null, "UPLOAD", "DOWNLOAD").forEach { direction ->
        val label =
            when (direction) {
                "UPLOAD" -> R.string.transfers_filter_uploads
                "DOWNLOAD" -> R.string.transfers_filter_downloads
                else -> R.string.transfers_filter_all
            }
        FilterChip(
            selected = filters.direction == direction,
            onClick = { onChange(filters.copy(direction = direction)) },
            label = { Text(stringResource(label)) },
        )
    }
}

@Composable
private fun <T> TransferFilterMenu(
    selected: Boolean,
    label: Int,
    options: List<T>,
    optionLabel: (T) -> Int,
    onSelect: (T) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    Box {
        FilterChip(
            selected = selected,
            onClick = { expanded = true },
            label = { Text(stringResource(label)) },
        )
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(stringResource(optionLabel(option))) },
                    onClick = {
                        onSelect(option)
                        expanded = false
                    },
                )
            }
        }
    }
}

@Composable
private fun TransferDateFilter(
    filters: TransferFilters,
    onChange: (TransferFilters) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    var customDates by remember { mutableStateOf(false) }
    Box {
        FilterChip(
            selected = filters.startDate != null,
            onClick = { expanded = true },
            label = { Text(dateFilterLabel(filters)) },
        )
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            listOf(
                R.string.transfers_filter_any_date to null,
                R.string.transfers_filter_today to 1L,
                R.string.transfers_filter_week to 7L,
                R.string.transfers_filter_month to 30L,
            ).forEach { (label, days) ->
                DropdownMenuItem(
                    text = { Text(stringResource(label)) },
                    onClick = {
                        val today = LocalDate.now()
                        onChange(
                            filters.copy(
                                startDate = days?.let { today.minusDays(it - 1) },
                                endDate = days?.let { today },
                            ),
                        )
                        expanded = false
                    },
                )
            }
            DropdownMenuItem(
                text = { Text(stringResource(R.string.transfers_filter_custom)) },
                onClick = {
                    expanded = false
                    customDates = true
                },
            )
        }
    }
    if (customDates) {
        TransferDateRangeDialog(filters, onChange, onDismiss = { customDates = false })
    }
}

@Composable
private fun dateFilterLabel(filters: TransferFilters): String {
    val start = filters.startDate ?: return stringResource(R.string.transfers_filter_any_date)
    val format = DateTimeFormatter.ofLocalizedDate(FormatStyle.SHORT)
    return stringResource(
        R.string.transfers_filter_date_range,
        start.format(format),
        (filters.endDate ?: start).format(format),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TransferDateRangeDialog(
    filters: TransferFilters,
    onChange: (TransferFilters) -> Unit,
    onDismiss: () -> Unit,
) {
    val picker =
        rememberDateRangePickerState(
            initialSelectedStartDateMillis =
                filters.startDate
                    ?.atStartOfDay(ZoneOffset.UTC)
                    ?.toInstant()
                    ?.toEpochMilli(),
            initialSelectedEndDateMillis =
                filters.endDate
                    ?.atStartOfDay(ZoneOffset.UTC)
                    ?.toInstant()
                    ?.toEpochMilli(),
        )
    DatePickerDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(
                enabled = picker.selectedStartDateMillis != null && picker.selectedEndDateMillis != null,
                onClick = {
                    onChange(
                        filters.copy(
                            startDate = picker.selectedStartDateMillis?.let(::pickerLocalDate),
                            endDate = picker.selectedEndDateMillis?.let(::pickerLocalDate),
                        ),
                    )
                    onDismiss()
                },
            ) { Text(stringResource(R.string.transfers_ok)) }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.transfers_cancel)) }
        },
    ) {
        DateRangePicker(
            state = picker,
            modifier = Modifier.heightIn(max = OpenCloudDimensions.TransferDateRangePickerHeight),
            title = {
                Text(
                    stringResource(R.string.transfers_filter_started_hint),
                    Modifier.padding(OpenCloudDimensions.SpacingMd),
                )
            },
        )
    }
}

private fun pickerLocalDate(timestamp: Long): LocalDate =
    Instant.ofEpochMilli(timestamp).atZone(ZoneOffset.UTC).toLocalDate()

private fun statusFilterLabel(status: TransferStatusFilter): Int =
    when (status) {
        TransferStatusFilter.ALL -> R.string.transfers_filter_all_statuses
        TransferStatusFilter.ACTIVE -> R.string.transfers_active_queued
        TransferStatusFilter.ATTENTION -> R.string.transfers_needs_attention
        TransferStatusFilter.SUCCEEDED -> R.string.transfers_status_succeeded
        TransferStatusFilter.CANCELLED -> R.string.transfers_status_cancelled
    }

private fun fileTypeLabel(type: TransferFileType): Int =
    when (type) {
        TransferFileType.ALL -> R.string.transfers_filter_all_types
        TransferFileType.IMAGES -> R.string.transfers_filter_images
        TransferFileType.VIDEOS -> R.string.transfers_filter_videos
        TransferFileType.DOCUMENTS -> R.string.transfers_filter_documents
        TransferFileType.AUDIO -> R.string.transfers_filter_audio
        TransferFileType.OTHER -> R.string.transfers_filter_other
    }
