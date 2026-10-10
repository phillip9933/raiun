package eu.opencloud.android.next.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.ListItem
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import dev.offlinescan.core.ScanOutput
import dev.offlinescan.core.ScanResult
import dev.offlinescan.ui.ScannerFlow
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.VaultScanTempSession
import eu.opencloud.android.next.core.sync.VaultScanTempStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.File
import java.io.InputStream

/**
 * Foreground-only encrypted scan. The callback must capture the current unlocked route session.
 * SDK outputs stay in non-backed-up app-private storage until upload or explicit discard.
 */
@Composable
internal fun VaultScannerRoute(
    destinationLabel: String,
    isSessionValid: () -> Boolean,
    upload: suspend (name: String, source: InputStream, size: Long, mimeType: String) -> Unit,
    onClose: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val scope = rememberCoroutineScope()
    val scanSession = remember(context) { createVaultScanSession(context) }
    var uploading by remember(scanSession) { mutableStateOf(false) }
    var error by remember(scanSession) { mutableStateOf(false) }
    var confirmDiscard by remember(scanSession) { mutableStateOf(false) }
    var closed by remember(scanSession) { mutableStateOf(false) }
    var uploadJob by remember(scanSession) { mutableStateOf<Job?>(null) }

    fun closeAndClean(cancelUpload: Boolean = true) {
        if (closed) return
        closed = true
        if (cancelUpload) uploadJob?.cancel()
        uploadJob = null
        runCatching { scanSession?.discard() }
        onClose()
    }

    // SDK outputs and direct network uploads both surface arbitrary I/O failures.
    @Suppress("TooGenericExceptionCaught")
    fun submit(output: ScanOutput) {
        if (uploading || closed) return
        uploading = true
        uploadJob =
            scope.launch {
                try {
                    requireSessionLease(isSessionValid)
                    uploadScanOutputs(scanSession, output.files, output.mimeType, isSessionValid, upload)
                    uploadJob = null
                    closeAndClean(cancelUpload = false)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    // Direct uploads can have an uncertain server outcome; never retry this plaintext output.
                    error = true
                    uploadJob = null
                    discardScanSession(scanSession)
                } finally {
                    uploading = false
                }
            }
    }

    DisposableEffect(lifecycle, scanSession) {
        val observer =
            LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_STOP) closeAndClean()
            }
        lifecycle.addObserver(observer)
        onDispose {
            lifecycle.removeObserver(observer)
            uploadJob?.cancel()
            runCatching { scanSession?.discard() }
        }
    }
    LaunchedEffect(scanSession, isSessionValid) {
        if (scanSession == null || !isSessionValid()) closeAndClean()
    }
    BackHandler(enabled = !uploading && !error) { confirmDiscard = true }

    VaultScannerSurface(
        session = scanSession,
        failed = error,
        uploading = uploading,
        destinationLabel = destinationLabel,
        onClose = ::closeAndClean,
        onComplete = ::submit,
        onFailure = {
            error = true
            discardScanSession(scanSession)
        },
    )
    if (confirmDiscard) {
        VaultScannerDiscardDialog(
            onDiscard = {
                confirmDiscard = false
                closeAndClean()
            },
            onKeep = { confirmDiscard = false },
        )
    }
}

@Composable
@Suppress("LongParameterList") // Three state inputs and three independent scanner events.
private fun VaultScannerSurface(
    session: VaultScanTempSession?,
    failed: Boolean,
    uploading: Boolean,
    destinationLabel: String,
    onClose: () -> Unit,
    onComplete: (ScanOutput) -> Unit,
    onFailure: () -> Unit,
) {
    Surface(Modifier.fillMaxSize()) {
        when {
            session == null || failed ->
                VaultScannerMessage(
                    stringResource(R.string.vault_scanner_failed),
                    stringResource(R.string.vault_scanner_close),
                    onClose,
                )
            uploading -> VaultScannerProgress()
            else ->
                ScannerFlow(
                    outputDirectory = session.outputDirectory,
                    saveDestination = { _ -> VaultScannerDestination(destinationLabel) },
                    includeDiagnostics = false,
                ) { result ->
                    when (result) {
                        is ScanResult.Completed -> onComplete(result.output)
                        ScanResult.Cancelled -> onClose()
                        is ScanResult.Failed -> onFailure()
                    }
                }
        }
    }
}

@Composable
private fun VaultScannerDestination(destinationLabel: String) {
    ListItem(
        headlineContent = { Text(stringResource(R.string.vault_scanner_fixed_destination)) },
        supportingContent = { Text(destinationLabel) },
        leadingContent = {
            Icon(Icons.Default.FolderOpen, contentDescription = null)
        },
        trailingContent = {
            Icon(Icons.Default.Lock, contentDescription = null)
        },
    )
}

private fun createVaultScanSession(context: android.content.Context): VaultScanTempSession? =
    try {
        VaultScanTempStore(context).createSession()
    } catch (_: java.io.IOException) {
        null
    } catch (_: SecurityException) {
        null
    } catch (_: IllegalStateException) {
        null
    }

private suspend fun uploadScanOutputs(
    session: VaultScanTempSession?,
    files: List<File>,
    mimeType: String,
    isSessionValid: () -> Boolean,
    upload: suspend (name: String, source: InputStream, size: Long, mimeType: String) -> Unit,
) {
    requireSessionLease(isSessionValid)
    val safeFiles = requireNotNull(session).validatedFiles(files)
    require(mimeType.isNotBlank())
    for (file in safeFiles) {
        requireSessionLease(isSessionValid)
        file.inputStream().use { source -> upload(file.name, source, file.length(), mimeType) }
    }
    requireSessionLease(isSessionValid)
}

private fun requireSessionLease(isSessionValid: () -> Boolean) {
    check(isSessionValid()) { "The encrypted Space session has expired." }
}

private fun discardScanSession(session: VaultScanTempSession?) {
    runCatching { session?.discard() }
}

@Composable
private fun VaultScannerProgress() {
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(OpenCloudDimensions.SpacingMd),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        CircularProgressIndicator()
        Text(stringResource(R.string.vault_scanner_uploading))
    }
}

@Composable
private fun VaultScannerMessage(
    message: String,
    actionLabel: String,
    onAction: () -> Unit,
) {
    Column(
        Modifier.fillMaxSize().safeDrawingPadding().padding(OpenCloudDimensions.SpacingMd),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd, Alignment.CenterVertically),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(message)
        FilledTonalButton(onClick = onAction) { Text(actionLabel) }
    }
}

@Composable
private fun VaultScannerDiscardDialog(
    onDiscard: () -> Unit,
    onKeep: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onKeep,
        title = { Text(stringResource(R.string.vault_scanner_discard_title)) },
        text = { Text(stringResource(R.string.vault_scanner_discard_body)) },
        confirmButton = {
            TextButton(onClick = onDiscard) { Text(stringResource(R.string.vault_scanner_discard)) }
        },
        dismissButton = {
            TextButton(onClick = onKeep) { Text(stringResource(R.string.vault_scanner_keep)) }
        },
    )
}
