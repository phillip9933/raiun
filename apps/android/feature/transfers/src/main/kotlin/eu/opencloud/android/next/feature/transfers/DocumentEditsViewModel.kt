package eu.opencloud.android.next.feature.transfers

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.DocumentEdit
import eu.opencloud.android.next.core.sync.DocumentEditInventory
import eu.opencloud.android.next.core.sync.DocumentEditReconciler
import eu.opencloud.android.next.core.sync.DocumentEditStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

data class DocumentEditsState(
    val inventory: DocumentEditInventory = DocumentEditInventory(emptyList()),
    val activeIds: Set<String> = emptySet(),
    val busy: Boolean = false,
    val message: DocumentEditsMessage? = null,
)

/** Stable UI message identifiers keep localized copy out of the ViewModel. */
enum class DocumentEditsMessage {
    RECOVERY_COPY_EXPORTED,
    ACTION_FAILED,
}

class DocumentEditsViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val drafts = DocumentEditStore(application)
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val lock = AppLock(application)
    private val mutableState = MutableStateFlow(DocumentEditsState())
    val state = mutableState.asStateFlow()
    private var account: String? = null
    private val actions = Mutex()

    fun load(accountId: String) {
        account = accountId
        refresh()
    }

    fun refresh() =
        action {
            DocumentEditReconciler(getApplication(), store).reconcile(requireNotNull(account))
        }

    fun discard(edit: DocumentEdit) =
        action {
            check(edit.accountId == account)
            drafts.discard(edit)
        }

    fun export(
        id: String,
        uri: Uri,
    ) = action {
        val saved = drafts.pending(requireNotNull(account)).single { it.id == id }
        check(lock.canOpenApp())
        val output = requireNotNull(getApplication<Application>().contentResolver.openOutputStream(uri, "w"))
        output.use { drafts.export(saved, it) { check(lock.canOpenApp()) } }
        mutableState.value = mutableState.value.copy(message = DocumentEditsMessage.RECOVERY_COPY_EXPORTED)
    }

    @Suppress("TooGenericExceptionCaught") // Display only a fixed safe message; retain drafts after failures.
    private fun action(block: suspend () -> Unit) {
        viewModelScope.launch(Dispatchers.IO) {
            actions.withLock {
                mutableState.value = state.value.copy(busy = true, message = null)
                try {
                    check(lock.canOpenApp() && store.account(requireNotNull(account))?.isActive == true)
                    block()
                    val inventory = drafts.inventory(requireNotNull(account))
                    val active =
                        inventory.edits
                            .filter { drafts.writerActive(it) }
                            .map { it.id }
                            .toSet()
                    mutableState.value = state.value.copy(inventory = inventory, activeIds = active)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    mutableState.value =
                        state.value.copy(message = DocumentEditsMessage.ACTION_FAILED)
                } finally {
                    mutableState.value = state.value.copy(busy = false)
                }
            }
        }
    }
}
