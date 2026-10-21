package eu.opencloud.android.next.feature.shares

import android.content.Context
import android.net.Uri
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.SharedDownloadFile
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import eu.opencloud.android.next.core.sync.SharedFolderBrowser
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import eu.opencloud.android.next.core.sync.SharedLocalReader
import eu.opencloud.android.next.core.sync.SharedRootDiscovery
import eu.opencloud.android.next.core.sync.SharedUploadDestinationResolver
import eu.opencloud.android.next.core.sync.TransferManager

internal class AndroidIncomingBrowserBackend(
    context: Context,
) : IncomingBrowserBackend {
    private val app = context.applicationContext
    private val discovery = SharedRootDiscovery.create(app)
    private val browser = SharedFolderBrowser.create(app)
    private val database = FileBrowserDatabase.create(app)

    override suspend fun upload(
        destination: SharedFolderRequest,
        sourceUri: String,
    ) {
        if (!AppLock(app).canOpenDocuments()) throw OpenCloudException(OpenCloudError.AccessDenied)
        TransferManager(app).enqueueSharedUpload(destination, Uri.parse(sourceUri))
    }

    private suspend fun uploadDestination(folder: SharedFolderRequest): SharedFolderRequest? =
        try {
            SharedUploadDestinationResolver.create(app).prepare(folder).request
        } catch (failure: OpenCloudException) {
            if (failure.error != OpenCloudError.AccessDenied) throw failure
            null
        }

    suspend fun changeCopy(
        file: IncomingBrowserItem.File,
        action: SharedCopyAction,
    ) {
        val reader = SharedLocalReader.create(app)
        when (action) {
            SharedCopyAction.KEEP -> {
                if (file.localCopy == null) {
                    if (!AppLock(app).canOpenDocuments()) throw OpenCloudException(OpenCloudError.AccessDenied)
                    TransferManager(app).enqueueSharedDownload(file.request, offlinePin = true)
                } else {
                    reader.setOfflinePinned(file.request, true)
                }
            }
            SharedCopyAction.TEMPORARY -> reader.setOfflinePinned(file.request, false)
            SharedCopyAction.REMOVE -> {
                val expected = file.localCopy
                if (expected == null || !reader.removeLocalCopy(expected)) {
                    throw OpenCloudException(OpenCloudError.PreconditionFailed)
                }
            }
        }
    }

    override suspend fun load(
        account: String,
        folder: SharedFolderRequest?,
    ): IncomingBrowserPage {
        val permit = AppLock(app).beginDocumentRead()
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        return if (folder == null) {
            val catalog = discovery.discover(account)
            val items =
                catalog.roots
                    .map {
                        IncomingBrowserItem.Folder(
                            it.name,
                            SharedFolderRequest(account, it.shareId, it.scopeId, it.rootItemId, "/"),
                            hidden = it.hidden,
                        )
                    }.sortedBy { it.name.lowercase() }
            IncomingBrowserPage(items, catalog.unavailable.size) { discovery.isCurrent(catalog) && permit() }
        } else {
            require(folder.account == account)
            val page = browser.openFolder(folder)
            val items =
                page.items.sortedWith(compareBy({ !it.folder }, { it.name.lowercase() })).map {
                    if (it.folder) {
                        IncomingBrowserItem.Folder(
                            it.name,
                            SharedFolderRequest(account, folder.share, folder.scope, it.id, it.path),
                        )
                    } else {
                        IncomingBrowserItem.File(
                            it.name,
                            SharedDownloadRequest(
                                account,
                                folder.share,
                                folder.scope,
                                SharedDownloadFile(it.id, it.path, it.size, it.eTag),
                            ),
                            it.mimeType,
                            database.sharedLocalFileDao().find(account, folder.scope, it.id),
                        )
                    }
                }
            IncomingBrowserPage(
                items,
                copies = database.sharedLocalFileDao().observe(account),
                uploadDestination = uploadDestination(folder),
                folderName = if (page.path == "/") page.location.name else page.path.substringAfterLast('/'),
            ) {
                browser.isCurrent(page) && permit()
            }
        }
    }
}
