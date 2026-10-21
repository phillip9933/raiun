package eu.opencloud.android.next.feature.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Palette
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
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.datastore.Appearance
import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Independent preference updates and navigation callbacks keep this screen stateless.
internal fun AppearanceSettingsScreen(
    state: UserSettings,
    onBack: () -> Unit,
    onAppearance: (Appearance) -> Unit,
    onFileDisplay: (FileDisplayOptions) -> Unit,
    language: SettingsLanguage,
    onPinnedNavigationItems: (List<eu.opencloud.android.next.core.datastore.NavigationItem>) -> Unit = {},
) {
    val themes = Appearance.entries.map { it to stringResource(it.resourceId()) }
    val resources = LocalContext.current.resources
    val configuredLanguages = remember(resources) { configuredLanguages(resources) }
    val languages = listOf("" to stringResource(R.string.settings_language_system)) + configuredLanguages
    Scaffold(topBar = {
        TopAppBar(title = { Text(stringResource(R.string.settings_appearance)) }, navigationIcon = {
            IconButton(onClick = onBack) {
                Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.settings_back))
            }
        })
    }) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
        ) {
            Text(stringResource(R.string.settings_theme_language), style = MaterialTheme.typography.titleSmall)
            Card {
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_theme)) },
                    leadingContent = { Icon(Icons.Default.Palette, null) },
                    colors =
                        ListItemDefaults.colors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                        ),
                    trailingContent = {
                        SettingsChoice(
                            stringResource(R.string.settings_change_appearance),
                            themes.first { it.first == state.appearance }.second,
                            themes.map { it.second },
                        ) { label ->
                            onAppearance(themes.first { it.second == label }.first)
                        }
                    },
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.settings_language)) },
                    leadingContent = { Icon(Icons.Default.Language, null) },
                    colors =
                        ListItemDefaults.colors(
                            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
                        ),
                    supportingContent = {
                        SettingsChoice(
                            stringResource(R.string.settings_change_language),
                            selectedLanguageChoice(languages, language.tag),
                            languages,
                            label = { it.second },
                        ) { choice ->
                            language.onSelect(choice.first)
                        }
                    },
                )
            }
            NavigationSettings(state.pinnedNavigationItems, onPinnedNavigationItems)
            Text(stringResource(R.string.settings_file_list), style = MaterialTheme.typography.titleSmall)
            Card { FileDisplaySettings(state.fileDisplay, onFileDisplay) }
        }
    }
}

/** Preserve regional choices such as pt-PT while accepting regional forms of language-only choices. */
internal fun selectedLanguageChoice(
    languages: List<Pair<String, String>>,
    languageTags: String,
): Pair<String, String> {
    val tag = languageTags.substringBefore(',')
    return languages.firstOrNull { it.first.equals(tag, ignoreCase = true) }
        ?: languages.firstOrNull { it.first.equals(tag.substringBefore('-'), ignoreCase = true) }
        ?: languages.first()
}
