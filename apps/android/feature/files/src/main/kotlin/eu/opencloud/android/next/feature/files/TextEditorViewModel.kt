package eu.opencloud.android.next.feature.files

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.DownloadExpectation
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.TextDraft
import eu.opencloud.android.next.core.sync.TextDraftStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

class TextEditorViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val drafts = TextDraftStore(application)
    private val writes = Mutex()
    private var saveJob: Job? = null
    private var opened = false
    private val mutableState = MutableStateFlow(TextEditorState())
    val state = mutableState.asStateFlow()

    fun load(
        account: String,
        space: String,
        resource: String,
    ) {
        if (opened) return
        opened = true
        mutableState.value = TextEditorState()
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    requireNotNull(store.account(account))
                    val item = requireNotNull(store.resource(account, space, resource))
                    mutableState.value = loadTextEditorState(getApplication(), item, drafts)
                }
            }.onFailure { failure(it) }
        }
    }

    fun edit(text: String) {
        val draft = state.value.draft ?: return
        if (state.value.busy || state.value.chooseDraft || draft.queuedId != null) return
        if (text.toByteArray().size > TextDraftStore.MAX_TEXT_BYTES) {
            mutableState.value =
                state.value.copy(
                    error =
                        getApplication<Application>().localizedString(R.string.document_text_too_large),
                )
        } else {
            mutableState.value = state.value.copy(draft = draft.copy(text = text), savingDraft = true, error = null)
            saveJob?.cancel()
            saveJob =
                viewModelScope.launch {
                    delay(250)
                    persist()
                }
        }
    }

    private suspend fun persist() {
        runCatching {
            withContext(Dispatchers.IO) { writes.withLock { state.value.draft?.let(drafts::save) } }
            mutableState.value = state.value.copy(savingDraft = false, error = null)
        }.onFailure { failure(it) }
    }

    fun save() {
        val draft = state.value.draft ?: return
        if (state.value.busy || state.value.chooseDraft || draft.queuedId != null) return
        mutableState.value = state.value.copy(busy = true, error = null)
        viewModelScope.launch {
            saveJob?.cancelAndJoin()
            runCatching {
                val queued = withContext(Dispatchers.IO) { writes.withLock { drafts.submit(draft) } }
                mutableState.value = state.value.copy(draft = queued, busy = false, savingDraft = false)
            }.onFailure {
                // Submission may have persisted its identity before scheduling failed.
                val persisted =
                    withContext(Dispatchers.IO) {
                        drafts.read(draft.accountId, draft.spaceId, draft.resourceId)
                    }
                mutableState.value = state.value.copy(draft = persisted ?: draft)
                failure(it)
            }
        }
    }

    fun close(onClose: () -> Unit) {
        if (state.value.busy && state.value.draft != null) return
        viewModelScope.launch {
            saveJob?.cancelAndJoin()
            persist()
            if (state.value.error == null || state.value.draft == null) {
                opened = false
                onClose()
            }
        }
    }

    fun refresh() {
        val draft = state.value.draft ?: return
        viewModelScope.launch {
            runCatching {
                val updated = withContext(Dispatchers.IO) { writes.withLock { drafts.resume(draft) } }
                mutableState.value = state.value.copy(draft = updated, error = null)
            }.onFailure { failure(it) }
        }
    }

    fun resumeDraft() {
        mutableState.value = state.value.copy(chooseDraft = false)
    }

    fun discard(onClose: () -> Unit) {
        val draft = state.value.draft ?: return
        if (state.value.busy || draft.queuedId != null) return
        mutableState.value = state.value.copy(busy = true)
        viewModelScope.launch {
            saveJob?.cancelAndJoin()
            runCatching {
                withContext(Dispatchers.IO) { writes.withLock { drafts.discard(draft) } }
                opened = false
                mutableState.value = TextEditorState()
                onClose()
            }.onFailure { failure(it) }
        }
    }

    private fun failure(error: Throwable) {
        val message =
            if (error is java.nio.charset.CharacterCodingException) {
                getApplication<Application>().localizedString(R.string.document_not_utf8)
            } else {
                error.toOpenCloudError().safeMessage(getApplication())
            }
        mutableState.value = state.value.copy(busy = false, savingDraft = false, error = message)
    }
}

data class TextEditorState(
    val draft: TextDraft? = null,
    val busy: Boolean = true,
    val savingDraft: Boolean = false,
    val error: String? = null,
    val serverChanged: Boolean = false,
    val chooseDraft: Boolean = false,
)

internal fun canEditText(resource: ResourceEntity): Boolean {
    val supported =
        resource.mimeType?.startsWith("text/") == true ||
            resource.name.substringAfterLast('.').lowercase() in
            setOf("txt", "md", "markdown", "json", "xml", "yaml", "yml", "csv", "log", "ini", "conf")
    val editableVersion = DownloadExpectation(resource.sizeBytes, resource.eTag).strongETag != null
    if (!supported || !editableVersion) return false
    return resource.kind == ResourceKind.FILE && resource.sizeBytes in 0L..TextDraftStore.MAX_TEXT_BYTES.toLong()
}
