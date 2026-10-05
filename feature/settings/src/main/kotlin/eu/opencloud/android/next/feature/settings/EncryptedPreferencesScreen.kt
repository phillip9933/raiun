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
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultKeyStore
import eu.opencloud.android.next.core.security.VaultPreferenceEntry
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultPreferences
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URI

@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("CyclomaticComplexMethod") // Inventory and revocation keep failure and cancellation paths explicit.
internal fun EncryptedPreferencesScreen(
    accountId: String?,
    onNavigateBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    val preferences = remember(context) { VaultPreferences(context) }
    val keyStore = remember(context) { VaultKeyStore(context) }
    val scope = rememberCoroutineScope()
    var revision by remember(accountId) { mutableIntStateOf(0) }
    var entries by remember(accountId) { mutableStateOf<List<EncryptedPreferenceRow>>(emptyList()) }
    var loading by remember(accountId) { mutableStateOf(true) }
    var busy by remember(accountId) { mutableStateOf(false) }
    var error by remember(accountId) { mutableStateOf(false) }
    var resetError by remember(accountId) { mutableStateOf(false) }
    var pendingReset by remember(accountId) { mutableStateOf<EncryptedPreferenceRow?>(null) }

    LaunchedEffect(accountId, revision) {
        loading = true
        error = false
        try {
            val loaded = withContext(Dispatchers.IO) { loadEncryptedPreferences(accountId, preferences, keyStore) }
            entries = loaded.first
            error = loaded.second
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            entries = emptyList()
            error = true
        } finally {
            loading = false
        }
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.settings_encrypted_preferences)) },
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
            Text(
                stringResource(R.string.settings_encrypted_preferences_explanation),
                style = MaterialTheme.typography.bodyMedium,
            )
            if (resetError) Text(stringResource(R.string.settings_encrypted_reset_failed))
            if (error) Text(stringResource(R.string.settings_encrypted_preferences_failed))
            when {
                loading -> CircularProgressIndicator()
                entries.isEmpty() && !error -> Text(stringResource(R.string.settings_encrypted_preferences_empty))
                else ->
                    entries.forEach { row ->
                        EncryptedPreferenceCard(row, busy) { pendingReset = row }
                    }
            }
        }
    }
    pendingReset?.let { row ->
        AlertDialog(
            onDismissRequest = { if (!busy) pendingReset = null },
            title = { Text(stringResource(R.string.settings_encrypted_reset_title)) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                    Text(
                        stringResource(
                            R.string.settings_encrypted_reset_explanation,
                            row.entry?.title ?: stringResource(R.string.settings_encrypted_unknown_location),
                        ),
                    )
                    Text(stringResource(R.string.settings_encrypted_reset_files_unchanged))
                }
            },
            confirmButton = {
                Button(
                    enabled = !busy,
                    onClick = {
                        if (row.identity.accountId != accountId) return@Button
                        busy = true
                        resetError = false
                        scope.launch {
                            try {
                                withContext(NonCancellable + Dispatchers.IO) {
                                    keyStore.forget(row.identity)
                                    preferences.remove(row.identity)
                                }
                                pendingReset = null
                                revision++
                            } catch (cancelled: CancellationException) {
                                throw cancelled
                            } catch (_: Exception) {
                                resetError = true
                                pendingReset = null
                            } finally {
                                busy = false
                            }
                        }
                    },
                ) {
                    Text(stringResource(resetActionLabel(row.enrolled)))
                }
            },
            dismissButton = {
                TextButton(enabled = !busy, onClick = { pendingReset = null }) {
                    Text(stringResource(R.string.settings_cancel))
                }
            },
        )
    }
}

private fun resetActionLabel(enrolled: Boolean): Int =
    if (enrolled) R.string.settings_encrypted_use_password else R.string.settings_encrypted_ask_again

internal data class EncryptedPreferenceRow(
    val identity: VaultIdentity,
    val entry: VaultPreferenceEntry?,
    val enrolled: Boolean,
)

private fun loadEncryptedPreferences(
    accountId: String?,
    preferences: VaultPreferences,
    keyStore: VaultKeyStore,
): Pair<List<EncryptedPreferenceRow>, Boolean> {
    if (accountId == null) return emptyList<EncryptedPreferenceRow>() to false
    // A corrupt offer marker must not hide a valid biometric envelope that can still be revoked.
    val (known, metadataFailed) =
        try {
            preferences.entries().filter { it.identity.accountId == accountId } to false
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            emptyList<VaultPreferenceEntry>() to true
        }
    val enrolled = keyStore.enrolledIdentities().filter { it.accountId == accountId }.toSet()
    val rows = known.map { entry -> EncryptedPreferenceRow(entry.identity, entry, entry.identity in enrolled) }
    val knownIdentities = known.mapTo(mutableSetOf()) { it.identity }
    return (rows + (enrolled - knownIdentities).map { EncryptedPreferenceRow(it, null, true) })
        .sortedWith(
            compareBy(String.CASE_INSENSITIVE_ORDER) { row: EncryptedPreferenceRow -> row.entry?.title.orEmpty() },
        ) to
        metadataFailed
}

@Composable
private fun EncryptedPreferenceCard(
    row: EncryptedPreferenceRow,
    busy: Boolean,
    onReset: () -> Unit,
) {
    val kind =
        when (row.entry?.targetKind) {
            VaultPreferenceTargetKind.FOLDER -> stringResource(R.string.settings_encrypted_folder)
            VaultPreferenceTargetKind.SPACE -> stringResource(R.string.settings_encrypted_space)
            null -> stringResource(R.string.settings_encrypted_unknown_location)
        }
    val status =
        when {
            row.entry?.status == VaultPreferenceStatus.DECLINED -> stringResource(R.string.settings_encrypted_declined)
            row.enrolled -> stringResource(R.string.settings_encrypted_enrolled)
            else -> stringResource(R.string.settings_encrypted_key_unavailable)
        }
    val host =
        remember(row.identity.canonicalServer) {
            runCatching { URI(row.identity.canonicalServer).host }.getOrNull().orEmpty()
        }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            Modifier.fillMaxWidth().padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            ListItem(
                headlineContent = {
                    Text(row.entry?.title ?: stringResource(R.string.settings_encrypted_unknown_location))
                },
                supportingContent = { Text(stringResource(R.string.settings_encrypted_entry_description, kind, host)) },
                leadingContent = { Icon(Icons.Default.Fingerprint, null) },
                colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.surfaceContainerHighest),
            )
            Text(status, style = MaterialTheme.typography.bodyMedium)
            FilledTonalButton(onClick = onReset, enabled = !busy) {
                Text(
                    stringResource(
                        if (row.enrolled) {
                            R.string.settings_encrypted_use_password
                        } else {
                            R.string.settings_encrypted_ask_again
                        },
                    ),
                )
            }
        }
    }
}
