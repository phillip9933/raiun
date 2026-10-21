package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import kotlinx.coroutines.CancellationException

class DocumentEditReconciler(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
    private val enqueue: suspend (DocumentEdit) -> Unit = { DocumentEditStore(context).submit(it) },
) {
    private val drafts = DocumentEditStore(context)

    suspend fun reconcile() {
        store.activeAccounts().forEach { reconcile(it.id) }
    }

    // Each retained journal can retry independently; no raw failure is persisted.
    @Suppress("TooGenericExceptionCaught")
    suspend fun reconcile(accountId: String) {
        if (store.account(accountId)?.isActive != true) return
        drafts.pending(accountId).forEach { edit ->
            try {
                reconcileEdit(edit)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // Keep this draft available for recovery; do not prevent recovery of the next draft.
            }
        }
    }

    private suspend fun reconcileEdit(edit: DocumentEdit) {
        when (edit.state) {
            DocumentEditState.READY -> {
                val space = store.space(edit.accountId, edit.spaceId)
                val resource = store.resource(edit.accountId, edit.spaceId, edit.resourceId)
                val available = space != null && !space.isDeleted && !space.isDisabled
                if (available && resource?.path == edit.path) enqueue(edit) else drafts.requireReview(edit)
            }
            DocumentEditState.SUBMITTED -> {
                val transfer = store.transfer(edit.id) ?: return
                check(transfer.accountId == edit.accountId && transfer.spaceId == edit.spaceId)
                check(transfer.direction == "UPLOAD")
                when (transfer.state) {
                    "SUCCEEDED" -> drafts.settleSubmission(edit, succeeded = true)
                    "CANCELLED" -> drafts.settleSubmission(edit, succeeded = false)
                    else -> Unit // Missing history is not proof that the upload succeeded; preserve the draft.
                }
            }
            DocumentEditState.OPEN, DocumentEditState.REVIEW -> Unit
        }
    }
}
