package eu.opencloud.android.next.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
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
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import eu.opencloud.android.next.core.ui.R as UiR

@OptIn(ExperimentalMaterial3Api::class)
@Composable
// Page navigation, volatile edit and discard are one secure dialog.
@Suppress("LongParameterList", "CyclomaticComplexMethod")
internal fun EncryptedPagedTextPreview(
    preview: VaultRoutePreview,
    saving: Boolean,
    saveError: VaultRouteError?,
    onSaveRange: (VaultRoutePreview, offset: Long, length: Long, bytes: ByteArray) -> Unit,
    onDismiss: () -> Unit,
    onOpenWith: (() -> Unit)? = null,
) {
    val backing = requireNotNull(preview.backing)
    var offset by remember(backing) { mutableLongStateOf(0L) }
    var history by remember(backing) { mutableStateOf(emptyList<Long>()) }
    var editing by remember(backing) { mutableStateOf(false) }
    var draft by remember(backing) { mutableStateOf("") }
    var confirmDiscard by remember(backing) { mutableStateOf(false) }
    var afterDiscard by remember(backing) { mutableStateOf<(() -> Unit)?>(null) }
    var tooLarge by remember(backing) { mutableStateOf(false) }
    var callbackFailed by remember(backing) { mutableStateOf(false) }
    var pageNumber by remember(backing) { mutableIntStateOf(1) }
    val page by rememberEncryptedTextPage(backing, offset)
    val failed = page?.length == -1
    val dirty = editing && page != null && draft != page!!.text
    DisposableEffect(backing) { onDispose { draft = "" } }

    fun discardOr(action: () -> Unit) {
        if (saving) return
        if (dirty) {
            afterDiscard = action
            confirmDiscard = true
        } else {
            draft = ""
            editing = false
            action()
        }
    }

    fun navigate(next: Boolean) {
        val current = page ?: return
        discardOr {
            if (next && current.hasNext) {
                history = history + offset
                offset += current.length
                pageNumber++
            } else if (!next && history.isNotEmpty()) {
                offset = history.last()
                history = history.dropLast(1)
                pageNumber--
            }
        }
    }

    BackHandler { discardOr { onDismiss() } }
    Dialog(
        onDismissRequest = { discardOr { onDismiss() } },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn, usePlatformDefaultWidth = false),
    ) {
        if (editing && page != null && !failed) {
            EncryptedTextEditorScreen(
                title = "${preview.title} · ${stringResource(R.string.vault_paged_text_part, pageNumber)}",
                text = draft,
                saving = saving,
                editable = preview.editable && dirty,
                tooLarge = tooLarge,
                error = if (callbackFailed) VaultRouteError.OPERATION else saveError,
                onChange = { changed ->
                    if (changed.length <= MAX_PAGE_EDIT_CHARS) {
                        draft = changed
                        tooLarge = false
                    } else {
                        tooLarge = true
                    }
                },
                onSave = {
                    val encoded = encodeEncryptedTextPage(draft)
                    if (encoded == null || encoded.size > MAX_PAGE_EDIT_BYTES) {
                        encoded?.fill(0)
                        tooLarge = true
                    } else {
                        callbackFailed = false
                        try {
                            onSaveRange(preview, page!!.offset, page!!.length.toLong(), encoded)
                        } catch (_: RuntimeException) {
                            encoded.fill(0)
                            callbackFailed = true
                        }
                    }
                },
                onCancel = { discardOr { editing = false } },
                onClose = { discardOr { onDismiss() } },
            )
        } else {
            EncryptedPagedTextViewer(
                preview = preview,
                page = page,
                failed = failed,
                pageNumber = pageNumber,
                saving = saving,
                hasPrevious = history.isNotEmpty(),
                onOpenWith = onOpenWith,
                onDismiss = { discardOr { onDismiss() } },
                onEdit = {
                    draft = requireNotNull(page).text
                    editing = true
                },
                onPrevious = { navigate(false) },
                onNext = { navigate(true) },
            )
        }
    }
    if (confirmDiscard) {
        EncryptedPagedTextDiscardDialog(
            onCancel = {
                confirmDiscard = false
                afterDiscard = null
            },
            onDiscard = {
                confirmDiscard = false
                draft = ""
                editing = false
                afterDiscard?.invoke()
                afterDiscard = null
            },
        )
    }
}

@Composable
@OptIn(ExperimentalMaterial3Api::class)
@Suppress("LongParameterList") // Viewer state and independent paging actions.
private fun EncryptedPagedTextViewer(
    preview: VaultRoutePreview,
    page: EncryptedTextPage?,
    failed: Boolean,
    pageNumber: Int,
    saving: Boolean,
    hasPrevious: Boolean,
    onOpenWith: (() -> Unit)?,
    onDismiss: () -> Unit,
    onEdit: () -> Unit,
    onPrevious: () -> Unit,
    onNext: () -> Unit,
) {
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(preview.title, maxLines = 1) },
                navigationIcon = {
                    IconButton(onClick = { onDismiss() }, enabled = !saving) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, stringResource(R.string.vault_close))
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
                onOpenWith?.let { open ->
                    TextButton(onClick = open, enabled = !saving) {
                        Text(stringResource(UiR.string.preview_open_with))
                    }
                }
                if (preview.editable && !failed && page != null) {
                    TextButton(onClick = { onEdit() }) {
                        Text(stringResource(UiR.string.preview_edit))
                    }
                }
            }
            Text(
                stringResource(R.string.vault_paged_text_part, pageNumber),
                Modifier.padding(OpenCloudDimensions.SpacingMd),
            )
            Box(Modifier.weight(1f).fillMaxWidth()) {
                when {
                    page == null -> CircularProgressIndicator()
                    failed -> Text(stringResource(UiR.string.preview_failed))
                    else ->
                        SelectionContainer {
                            Text(
                                page!!.text,
                                Modifier
                                    .fillMaxSize()
                                    .verticalScroll(rememberScrollState())
                                    .padding(OpenCloudDimensions.SpacingMd),
                            )
                        }
                }
            }
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) {
                TextButton(onClick = { onPrevious() }, enabled = hasPrevious && !saving) {
                    Text(stringResource(UiR.string.preview_previous))
                }
                TextButton(onClick = { onNext() }, enabled = page?.hasNext == true && !saving) {
                    Text(stringResource(UiR.string.preview_next))
                }
            }
        }
    }
}

@Composable
private fun rememberEncryptedTextPage(
    backing: EncryptedPreviewBacking,
    offset: Long,
): State<EncryptedTextPage?> =
    produceState<EncryptedTextPage?>(null, backing, offset) {
        value =
            try {
                withContext(Dispatchers.IO) { readEncryptedTextPage(backing, offset) }
            } catch (_: IOException) {
                EncryptedTextPage(offset, -1, "", false)
            }
    }

@Composable
private fun EncryptedPagedTextDiscardDialog(
    onCancel: () -> Unit,
    onDiscard: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.vault_text_discard_title)) },
        text = { Text(stringResource(R.string.vault_text_discard_message)) },
        confirmButton = {
            TextButton(onClick = onDiscard) { Text(stringResource(R.string.vault_text_discard)) }
        },
        dismissButton = {
            TextButton(onClick = onCancel) { Text(stringResource(R.string.vault_cancel)) }
        },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
    )
}

internal data class EncryptedTextPage(
    val offset: Long,
    val length: Int,
    val text: String,
    val hasNext: Boolean,
)

/** Reads and strictly decodes one page, shortening its tail only to preserve a UTF-8 boundary. */
internal fun readEncryptedTextPage(
    backing: EncryptedPreviewBacking,
    offset: Long,
): EncryptedTextPage {
    require(offset in 0..backing.size)
    val remaining = backing.size - offset
    val requested = minOf(TEXT_PAGE_BYTES.toLong(), remaining).toInt()
    val bytes = ByteArray(requested)
    try {
        if (backing.read(offset, requested, bytes) != requested) throw IOException("Encrypted text page ended early.")
        val boundary = if (remaining <= TEXT_PAGE_BYTES) requested else completeUtf8Boundary(bytes, requested)
        val text = strictPageText(bytes, boundary) ?: throw IOException("Encrypted text is not valid UTF-8.")
        return EncryptedTextPage(offset, boundary, text, offset + boundary < backing.size)
    } finally {
        bytes.fill(0)
    }
}

private fun completeUtf8Boundary(
    bytes: ByteArray,
    requested: Int,
): Int {
    for (length in requested downTo maxOf(1, requested - 3)) {
        if (strictPageText(bytes, length) != null) return length
    }
    throw IOException("Encrypted text is not valid UTF-8.")
}

private fun strictPageText(
    bytes: ByteArray,
    length: Int,
): String? =
    runCatching {
        StandardCharsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes, 0, length))
            .toString()
    }.getOrNull()?.takeUnless { '\u0000' in it }

internal fun encodeEncryptedTextPage(text: String): ByteArray? =
    runCatching {
        val encoded =
            StandardCharsets.UTF_8
                .newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(text))
        ByteArray(encoded.remaining()).also { encoded.get(it) }
    }.getOrNull()

private const val TEXT_PAGE_BYTES = 64 * 1024
private const val MAX_PAGE_EDIT_CHARS = 256 * 1024
private const val MAX_PAGE_EDIT_BYTES = 512 * 1024
