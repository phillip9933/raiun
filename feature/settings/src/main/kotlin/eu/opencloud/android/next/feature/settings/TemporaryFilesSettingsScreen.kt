package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.History
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun TemporaryFilesSettingsScreen(
    retentionHours: Int,
    onSetRetention: (Int) -> Unit,
    onClearTemporary: () -> Unit,
    onNavigateBack: () -> Unit,
) {
    val options =
        listOf(
            0 to stringResource(R.string.settings_retention_never),
            1 to pluralStringResource(R.plurals.settings_retention_hours, 1, 1),
            12 to pluralStringResource(R.plurals.settings_retention_hours, 12, 12),
            24 to pluralStringResource(R.plurals.settings_retention_days, 1, 1),
            720 to pluralStringResource(R.plurals.settings_retention_days, 30, 30),
        )
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_temporary_files)) },
                navigationIcon = {
                    IconButton(onClick = onNavigateBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.settings_back))
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
        ) {
            Card(modifier = Modifier.fillMaxWidth()) {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_delete_temporary_copies)) },
                    supportingContent = {
                        Text(
                            stringResource(R.string.settings_temporary_copy_retention_description),
                        )
                    },
                    leadingContent = { Icon(Icons.Default.History, null) },
                    trailingContent = {
                        SettingsChoice(
                            stringResource(R.string.settings_change_copy_retention),
                            options.firstOrNull { it.first == retentionHours }?.second ?: options.first().second,
                            options.map { it.second },
                        ) { selected -> onSetRetention(options.first { it.second == selected }.first) }
                    },
                    colors =
                        ListItemDefaults.colors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                        ),
                )
            }
            TemporaryCleanupButton(onClearTemporary)
        }
    }
}
