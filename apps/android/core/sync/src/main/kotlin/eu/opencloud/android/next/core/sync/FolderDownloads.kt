package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.security.AppLock
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Queues bounded, freshly resolved descendants through the same durable per-file transfer pipeline. */
class FolderDownloads(
    private val context: Context,
) {
    suspend fun shared(
        root: SharedFolderRequest,
        onQueued: suspend (Int) -> Unit,
    ): Int {
        val permit = AppLock(context).beginAppAction()
        val browser = SharedFolderBrowser.create(context)
        val resolver = SharedDownloadResolver.create(context)
        val transfers = TransferManager(context)
        val pending = ArrayDeque<SharedFolderRequest>().apply { add(root) }
        val visited = mutableSetOf<String>()
        var count = 0
        while (pending.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            check(permit())
            val folder = pending.removeFirst()
            check(visited.add(folder.remoteId) && visited.size <= 10000) { "Folder traversal limit reached." }
            val page = browser.openFolder(folder)
            for (item in page.items) {
                currentCoroutineContext().ensureActive()
                check(permit() && browser.isCurrent(page))
                if (item.folder) {
                    check(visited.size + pending.size < 10000) { "Folder traversal limit reached." }
                    pending.add(folder.copy(remoteId = item.id, path = item.path))
                } else {
                    check(count < 10000) { "Download queue limit reached." }
                    transfers.enqueueSharedDownload(resolver.capture(page, item.id), offlinePin = true)
                    onQueued(++count)
                }
            }
        }
        return count
    }

    suspend fun space(
        account: String,
        space: String,
        onQueued: suspend (Int) -> Unit,
    ): Int {
        val permit = AppLock(context).beginAppAction()
        val store = FileBrowserStore(FileBrowserDatabase.create(context))
        val folders = ProviderFolderOperations(context, store)
        val transfers = TransferManager(context, store)
        val pending = mutableListOf<String?>(null)
        val visited = mutableSetOf<String?>()
        var count = 0
        while (pending.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            check(permit())
            val folder = pending.removeAt(0)
            check(visited.add(folder) && visited.size <= 10000) { "Folder traversal limit reached." }
            folders.refresh(account, space, folder, permit)
            for (item in store.children(account, space, folder)) {
                currentCoroutineContext().ensureActive()
                check(permit())
                if (item.kind == ResourceKind.FOLDER) {
                    check(visited.size + pending.size < 10000) { "Folder traversal limit reached." }
                    pending.add(item.remoteId)
                } else {
                    check(count < 10000) { "Download queue limit reached." }
                    transfers.enqueueDownload(item, offlinePin = true)
                    onQueued(++count)
                }
            }
        }
        return count
    }
}
