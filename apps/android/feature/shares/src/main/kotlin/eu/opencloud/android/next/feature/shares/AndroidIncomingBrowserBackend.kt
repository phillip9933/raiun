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
    private var rememberedFolder: SharedFolderRequest? = null
    private var rememberedPage: eu.opencloud.android.next.core.sync.SharedFolderPage? = null

    override suspend fun upload(
        destination: SharedFolderRequest,
        sourceUri: String,
    ) {
        if (!AppLock(app).canOpenDocuments()) throw OpenCloudException(OpenCloudError.AccessDenied)
        TransferManager(app).enqueueSharedUpload(destination, Uri.parse(sourceUri))
    }

    private suspend fun uploadDestination(
        folder: SharedFolderRequest,
        page: eu.opencloud.android.next.core.sync.SharedFolderPage,
    ): SharedFolderRequest? =
        try {
            SharedUploadDestinationResolver.create(app).prepare(folder, page).request
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
    ): IncomingBrowserPage = loadPage(account, folder, 0, refresh = true)

    override suspend fun loadPage(
        account: String,
        folder: SharedFolderRequest?,
        offset: Int,
        refresh: Boolean,
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
            val page =
                if (!refresh && rememberedFolder == folder) {
                    rememberedPage ?: browser.refreshFolder(folder)
                } else {
                    browser.refreshFolder(folder)
                }
            val initial = browser.displayPage(page, offset)
            val actualOffset = if (initial.second == 0) 0 else minOf(offset, ((initial.second - 1) / 256) * 256)
            val (entries, total) = if (actualOffset == offset) initial else browser.displayPage(page, actualOffset)
            rememberedFolder = folder
            rememberedPage = page
            val items =
                entries.map {
                    if (it.isFolder) {
                        IncomingBrowserItem.Folder(
                            it.name,
                            SharedFolderRequest(account, folder.share, folder.scope, it.remoteId, it.path),
                        )
                    } else {
                        IncomingBrowserItem.File(
                            it.name,
                            SharedDownloadRequest(
                                account,
                                folder.share,
                                folder.scope,
                                SharedDownloadFile(it.remoteId, it.path, it.sizeBytes, it.eTag),
                            ),
                            it.mimeType,
                            database.sharedLocalFileDao().find(account, folder.scope, it.remoteId),
                        )
                    }
                }
            IncomingBrowserPage(
                items,
                copies = database.sharedLocalFileDao().observePage(account, folder.scope, entries.map { it.remoteId }),
                offset = actualOffset,
                total = total,
                uploadDestination = uploadDestination(folder, page),
                folderName = if (page.path == "/") page.location.name else page.path.substringAfterLast('/'),
            ) {
                browser.isCurrent(page) && permit()
            }
        }
    }
}
