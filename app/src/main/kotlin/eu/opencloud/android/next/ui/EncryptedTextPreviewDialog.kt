package eu.opencloud.android.next.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.ui.FilePreviewScreen
import eu.opencloud.android.next.core.ui.FilePreviewState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

@Composable
// Cancellation, lock and save-failure branches must preserve volatile secure edits.
@Suppress("CyclomaticComplexMethod", "LongParameterList")
internal fun EncryptedTextPreviewDialog(
    preview: VaultRoutePreview,
    saving: Boolean,
    saveError: VaultRouteError?,
    onSaveText: (VaultRoutePreview, ByteArray) -> Unit,
    onDismiss: () -> Unit,
    onOpenWith: (() -> Unit)? = null,
) {
    var editing by remember(preview.bytes) { mutableStateOf(false) }
    var draft by remember(preview.bytes) { mutableStateOf<String?>(null) }
    var confirmDiscard by remember(preview.bytes) { mutableStateOf(false) }
    var discardClosesPreview by remember(preview.bytes) { mutableStateOf(false) }
    var tooLarge by remember(preview.bytes) { mutableStateOf(false) }
    var callbackFailed by remember(preview.bytes) { mutableStateOf(false) }
    val original by produceState(initialValue = DecodedText(false, null), preview.bytes) {
        val copy = preview.bytes.copyOf()
        try {
            value = DecodedText(true, withContext(Dispatchers.Default) { decodeStrictText(copy) })
        } finally {
            copy.fill(0)
        }
    }
    LaunchedEffect(preview.bytes, original.complete) {
        if (draft == null && original.complete) draft = original.text
    }
    val isDirty = editing && original.text != null && draft != original.text
    DisposableEffect(preview.bytes) {
        onDispose { draft = "" }
    }

    fun requestClose() {
        if (saving) return
        if (isDirty) {
            discardClosesPreview = true
            confirmDiscard = true
        } else {
            draft = ""
            onDismiss()
        }
    }

    BackHandler {
        if (saving) return@BackHandler
        when {
            isDirty -> {
                discardClosesPreview = false
                confirmDiscard = true
            }
            editing -> {
                draft = original.text
                editing = false
            }
            else -> onDismiss()
        }
    }

    Dialog(
        onDismissRequest = { requestClose() },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn, usePlatformDefaultWidth = false),
    ) {
        if (!editing) {
            EncryptedTextViewer(preview, original, ::requestClose, onOpenWith) {
                draft = original.text
                editing = true
            }
        } else {
            val error = if (callbackFailed) VaultRouteError.OPERATION else saveError
            EncryptedTextEditorScreen(
                title = preview.title,
                text = draft.orEmpty(),
                saving = saving,
                editable = preview.editable && draft != original.text,
                tooLarge = tooLarge,
                error = error,
                onChange = { draft = it },
                onSave = {
                    val bytes = encodeStrictText(draft.orEmpty())
                    if (bytes == null || bytes.size > MAX_VAULT_EDIT_TEXT_BYTES) {
                        bytes?.fill(0)
                        tooLarge = true
                    } else {
                        tooLarge = false
                        callbackFailed = false
                        try {
                            onSaveText(preview, bytes)
                        } catch (_: RuntimeException) {
                            bytes.fill(0)
                            callbackFailed = true
                        }
                    }
                },
                onCancel = {
                    if (isDirty) {
                        discardClosesPreview = false
                        confirmDiscard = true
                    } else {
                        draft = original.text
                        editing = false
                    }
                },
                onClose = { requestClose() },
            )
        }
    }
    if (confirmDiscard) {
        EncryptedTextDiscardDialog(
            onCancel = { confirmDiscard = false },
            onDiscard = {
                confirmDiscard = false
                draft = ""
                editing = false
                if (discardClosesPreview) onDismiss() else draft = original.text
            },
        )
    }
}

@Composable
private fun EncryptedTextViewer(
    preview: VaultRoutePreview,
    original: DecodedText,
    onClose: () -> Unit,
    onOpenWith: (() -> Unit)?,
    onEdit: () -> Unit,
) {
    FilePreviewScreen(
        name = preview.title,
        state =
            FilePreviewState(
                loading = !original.complete,
                text = original.text,
                failed = original.complete && original.text == null,
            ),
        onClose = onClose,
        onOpenWith = onOpenWith,
        onPage = {},
        onRetry = null,
        modifier = Modifier.fillMaxSize(),
        onEdit = if (preview.editable && original.text != null) onEdit else null,
    )
}

@Composable
private fun EncryptedTextDiscardDialog(
    onCancel: () -> Unit,
    onDiscard: () -> Unit,
) {
    androidx.compose.material3.AlertDialog(
        onDismissRequest = onCancel,
        title = { androidx.compose.material3.Text(stringResource(R.string.vault_text_discard_title)) },
        text = { androidx.compose.material3.Text(stringResource(R.string.vault_text_discard_message)) },
        confirmButton = {
            androidx.compose.material3.FilledTonalButton(onClick = onDiscard) {
                androidx.compose.material3.Text(stringResource(R.string.vault_text_discard))
            }
        },
        dismissButton = {
            androidx.compose.material3.TextButton(onClick = onCancel) {
                androidx.compose.material3.Text(stringResource(R.string.vault_cancel))
            }
        },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
    )
}

private data class DecodedText(
    val complete: Boolean,
    val text: String?,
)

private fun decodeStrictText(bytes: ByteArray): String? {
    if (bytes.size > MAX_TEXT_PREVIEW_BYTES) return null
    return runCatching {
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    }.getOrNull()?.takeUnless { text -> text.any { it.code == 0 } }
}

private fun encodeStrictText(text: String): ByteArray? {
    if (text.length > MAX_VAULT_EDIT_TEXT_BYTES) return null
    return runCatching {
        val encoded =
            StandardCharsets.UTF_8
                .newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(text))
        try {
            ByteArray(encoded.remaining()).also { encoded.get(it) }
        } finally {
            encoded.clear()
            while (encoded.hasRemaining()) encoded.put(0)
        }
    }.getOrNull()
}

private const val MAX_TEXT_PREVIEW_BYTES = 256 * 1024
