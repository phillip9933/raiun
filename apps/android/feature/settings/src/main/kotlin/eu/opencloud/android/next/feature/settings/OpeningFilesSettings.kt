package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.datastore.FileOpening
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@OptIn(ExperimentalMaterial3Api::class)
@Composable
internal fun OpeningFilesScreen(
    options: FileOpening,
    onChange: (FileOpening) -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(topBar = {
        TopAppBar(title = { Text(stringResource(R.string.settings_opening_files)) }, navigationIcon = {
            IconButton(
                onClick = onBack,
            ) { Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.settings_back)) }
        })
    }) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(
                    padding,
                ).verticalScroll(rememberScrollState())
                .padding(OpenCloudDimensions.SpacingMd),
        ) {
            OpeningFilesSettings(options, onChange)
        }
    }
}

@Composable
internal fun OpeningFilesSettings(
    options: FileOpening,
    onChange: (FileOpening) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd)) {
        Card {
            Column(Modifier.padding(OpenCloudDimensions.SpacingMd)) {
                Text(stringResource(R.string.settings_opening_description))
                OpeningChoice(
                    R.string.settings_opening_text,
                    options.externalText,
                ) { onChange(options.copy(externalText = it)) }
                OpeningChoice(
                    R.string.settings_opening_pdf,
                    options.externalPdf,
                ) { onChange(options.copy(externalPdf = it)) }
                OpeningChoice(
                    R.string.settings_opening_images,
                    options.externalImages,
                ) { onChange(options.copy(externalImages = it)) }
            }
        }
    }
}

@Composable
private fun OpeningChoice(
    label: Int,
    external: Boolean,
    onChange: (Boolean) -> Unit,
) {
    val title = stringResource(label)
    val choices =
        listOf(stringResource(R.string.settings_opening_raiun), stringResource(R.string.settings_opening_external))
    Column {
        Text(title, Modifier.padding(top = OpenCloudDimensions.SpacingSm))
        SettingsChoice(title, choices[if (external) 1 else 0], choices) { onChange(it == choices[1]) }
    }
}
