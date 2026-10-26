package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.RESOURCE_DIRECTORY_PAGE_SIZE
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
        return SharedDownloadTraversal(context, permit).run(root, onQueued)
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
            visitSpaceChildren(store, account, space, folder) { item ->
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

private suspend fun visitSpaceChildren(
    store: FileBrowserStore,
    account: String,
    space: String,
    folder: String?,
    visit: suspend (eu.opencloud.android.next.core.database.ResourceEntity) -> Unit,
) {
    var offset = 0
    do {
        currentCoroutineContext().ensureActive()
        val items = store.childrenPage(account, space, folder, offset)
        items.forEach { visit(it) }
        offset += items.size
    } while (items.size == RESOURCE_DIRECTORY_PAGE_SIZE)
}

private class SharedDownloadTraversal(
    private val context: Context,
    private val permit: () -> Boolean,
) {
    private val browser = SharedFolderBrowser.create(context)
    private val resolver = SharedDownloadResolver.create(context)
    private val transfers = TransferManager(context)
    private val pending = ArrayDeque<SharedFolderRequest>()
    private val visited = mutableSetOf<String>()
    private var count = 0

    suspend fun run(
        root: SharedFolderRequest,
        onQueued: suspend (Int) -> Unit,
    ): Int {
        pending.add(root)
        while (pending.isNotEmpty()) {
            currentCoroutineContext().ensureActive()
            check(permit())
            val folder = pending.removeFirst()
            check(visited.add(folder.remoteId) && visited.size <= 10000) { "Folder traversal limit reached." }
            visit(folder, onQueued)
        }
        return count
    }

    private suspend fun visit(
        folder: SharedFolderRequest,
        onQueued: suspend (Int) -> Unit,
    ) {
        val page = browser.refreshFolder(folder)
        var offset = 0
        do {
            check(permit() && browser.isCurrent(page))
            val (items, total) = browser.displayPage(page, offset)
            enqueueItems(folder, page, items, onQueued)
            offset += items.size
            check(items.isNotEmpty() || offset >= total)
        } while (offset < total)
    }

    private suspend fun enqueueItems(
        folder: SharedFolderRequest,
        page: SharedFolderPage,
        items: List<eu.opencloud.android.next.core.database.SharedFolderEntry>,
        onQueued: suspend (Int) -> Unit,
    ) {
        for (item in items) enqueueItem(folder, page, item, onQueued)
    }

    private suspend fun enqueueItem(
        folder: SharedFolderRequest,
        page: SharedFolderPage,
        item: eu.opencloud.android.next.core.database.SharedFolderEntry,
        onQueued: suspend (Int) -> Unit,
    ) {
        currentCoroutineContext().ensureActive()
        check(permit() && browser.isCurrent(page))
        if (item.isFolder) {
            check(visited.size + pending.size < 10000) { "Folder traversal limit reached." }
            pending.add(folder.copy(remoteId = item.remoteId, path = item.path))
        } else {
            check(count < 10000) { "Download queue limit reached." }
            transfers.enqueueSharedDownload(resolver.capture(page, item.remoteId), offlinePin = true)
            onQueued(++count)
        }
    }
}
