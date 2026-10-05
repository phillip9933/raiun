package eu.opencloud.android.next.feature.settings

import android.app.Application
import androidx.activity.compose.BackHandler
import androidx.appcompat.app.AppCompatDelegate
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.core.os.LocaleListCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.core.datastore.Appearance
import eu.opencloud.android.next.core.datastore.LocalDiagnostics
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.localizedQuantityString
import eu.opencloud.android.next.core.designsystem.localizedString
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.IOException

class SettingsViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val repository = SettingsRepository.create(application)
    val state = repository.settings.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), UserSettings())
    private val mutableDiagnostics = MutableStateFlow<String?>(null)
    val diagnostics = mutableDiagnostics.asStateFlow()

    fun setDiagnostics(enabled: Boolean) {
        viewModelScope.launch {
            try {
                LocalDiagnostics.setEnabled(getApplication(), enabled)
                mutableDiagnostics.value = null
            } catch (_: IOException) {
                mutableDiagnostics.value =
                    getApplication<Application>().localizedString(R.string.settings_diagnostics_update_failed)
            }
        }
    }

    fun showDiagnostics() {
        viewModelScope.launch {
            mutableDiagnostics.value =
                try {
                    LocalDiagnostics.read(getApplication()).ifEmpty {
                        getApplication<Application>().localizedString(R.string.settings_no_transfer_outcomes)
                    }
                } catch (_: IOException) {
                    getApplication<Application>().localizedString(R.string.settings_diagnostics_read_failed)
                }
        }
    }

    fun dismissDiagnostics() {
        mutableDiagnostics.value = null
    }

    fun setRetention(hours: Int) {
        viewModelScope.launch { repository.setTemporaryCopyRetentionHours(hours) }
    }

    fun setFileOpening(options: eu.opencloud.android.next.core.datastore.FileOpening) {
        viewModelScope.launch { repository.setFileOpening(options) }
    }

    fun setFileDisplay(options: eu.opencloud.android.next.core.datastore.FileDisplayOptions) {
        viewModelScope.launch { repository.setFileDisplay(options) }
    }

    fun clearTemporaryCopies() {
        viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            try {
                val count =
                    eu.opencloud.android.next.core.sync
                        .clearTemporaryCopies(getApplication())
                mutableDiagnostics.value =
                    getApplication<Application>().localizedQuantityString(
                        R.plurals.settings_temporary_copies_removed,
                        count,
                        count,
                    )
            } catch (_: IOException) {
                mutableDiagnostics.value =
                    getApplication<Application>().localizedString(R.string.settings_temporary_copies_remove_failed)
            }
        }
    }

    fun setAppearance(appearance: Appearance) {
        viewModelScope.launch { repository.setAppearance(appearance) }
    }
}

@Composable
@Suppress("LongParameterList") // Route dependencies and callbacks are explicit navigation inputs.
fun SettingsRoute(
    onNavigateBack: () -> Unit,
    onOpenBackupSettings: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: SettingsViewModel = viewModel(),
    accountId: String? = null,
) {
    val state by viewModel.state.collectAsState()
    val diagnostics by viewModel.diagnostics.collectAsState()
    SettingsScreen(
        state,
        onNavigateBack,
        onOpenBackupSettings,
        viewModel::setRetention,
        modifier,
        diagnostics =
            SettingsDiagnostics(
                diagnostics,
                viewModel::setDiagnostics,
                viewModel::showDiagnostics,
                viewModel::dismissDiagnostics,
            ),
        onSetAppearance = viewModel::setAppearance,
        accountId = accountId,
        onFileDisplay = viewModel::setFileDisplay,
        onFileOpening = viewModel::setFileOpening,
        onClearTemporary = viewModel::clearTemporaryCopies,
        languageTag = AppCompatDelegate.getApplicationLocales().toLanguageTags(),
        onLanguage = { AppCompatDelegate.setApplicationLocales(LocaleListCompat.forLanguageTags(it)) },
    )
}

data class SettingsDiagnostics(
    val text: String? = null,
    val onSetEnabled: (Boolean) -> Unit = {},
    val onRead: () -> Unit = {},
    val onDismiss: () -> Unit = {},
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Screen navigation, actions, modifier and diagnostics are explicit Compose inputs.
fun SettingsScreen(
    state: UserSettings,
    onNavigateBack: () -> Unit,
    onOpenBackupSettings: () -> Unit,
    onSetRetention: (Int) -> Unit,
    modifier: Modifier = Modifier,
    diagnostics: SettingsDiagnostics = SettingsDiagnostics(),
    onSetAppearance: (Appearance) -> Unit = {},
    onFileDisplay: (eu.opencloud.android.next.core.datastore.FileDisplayOptions) -> Unit = {},
    onClearTemporary: () -> Unit = {},
    languageTag: String = "",
    onLanguage: (String) -> Unit = {},
    onFileOpening: (eu.opencloud.android.next.core.datastore.FileOpening) -> Unit = {},
    accountId: String? = null,
) {
    var appearanceOpen by rememberSaveable { mutableStateOf(false) }
    var openingFiles by rememberSaveable { mutableStateOf(false) }
    var temporaryFilesOpen by rememberSaveable { mutableStateOf(false) }
    var encryptedPreferencesOpen by rememberSaveable { mutableStateOf(false) }
    var permissionsOpen by rememberSaveable { mutableStateOf(false) }
    BackHandler {
        when {
            openingFiles -> openingFiles = false
            appearanceOpen -> appearanceOpen = false
            temporaryFilesOpen -> temporaryFilesOpen = false
            encryptedPreferencesOpen -> encryptedPreferencesOpen = false
            permissionsOpen -> permissionsOpen = false
            else -> onNavigateBack()
        }
    }
    Box(modifier = modifier.fillMaxSize()) {
        when {
            openingFiles -> OpeningFilesScreen(state.fileOpening, onFileOpening) { openingFiles = false }
            appearanceOpen ->
                AppearanceSettingsScreen(
                    state,
                    { appearanceOpen = false },
                    onSetAppearance,
                    onFileDisplay,
                    SettingsLanguage(languageTag, onLanguage),
                )
            temporaryFilesOpen ->
                TemporaryFilesSettingsScreen(
                    retentionHours = state.temporaryCopyRetentionHours,
                    onSetRetention = onSetRetention,
                    onClearTemporary = onClearTemporary,
                    onNavigateBack = { temporaryFilesOpen = false },
                )
            encryptedPreferencesOpen ->
                EncryptedPreferencesScreen(
                    accountId = accountId,
                    onNavigateBack = { encryptedPreferencesOpen = false },
                )
            permissionsOpen ->
                PermissionsSettingsScreen(
                    onNavigateBack = { permissionsOpen = false },
                )
            else -> {
                Scaffold(
                    topBar = {
                        TopAppBar(
                            title = { Text(stringResource(R.string.settings_title)) },
                            navigationIcon = {
                                IconButton(onClick = onNavigateBack) {
                                    Icon(
                                        Icons.AutoMirrored.Filled.ArrowBack,
                                        contentDescription = stringResource(R.string.settings_back),
                                    )
                                }
                            },
                        )
                    },
                ) { padding ->
                    Column(Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState())) {
                        SettingsSections(
                            state,
                            { appearanceOpen = true },
                            onOpenBackupSettings,
                            diagnostics,
                            { encryptedPreferencesOpen = true },
                            { permissionsOpen = true },
                            { temporaryFilesOpen = true },
                            { openingFiles = true },
                        )
                    }
                }
                diagnostics.text?.let { text ->
                    AlertDialog(
                        onDismissRequest = diagnostics.onDismiss,
                        title = { Text(stringResource(R.string.settings_title)) },
                        text = { Text(text, modifier = Modifier.verticalScroll(rememberScrollState())) },
                        confirmButton = {
                            TextButton(
                                onClick = diagnostics.onDismiss,
                            ) { Text(stringResource(R.string.settings_close)) }
                        },
                    )
                }
            }
        }
    }
}
