package eu.opencloud.android.next.core.documentsprovider

import android.database.Cursor
import android.database.MatrixCursor
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract.Document
import android.provider.DocumentsContract.Root
import android.provider.DocumentsProvider
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.sync.ProviderFolderOperations
import eu.opencloud.android.next.core.sync.TransferManager
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.io.FileNotFoundException

class OpenCloudDocumentsProvider : DocumentsProvider() {
    private val openScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val openSlots = java.util.concurrent.Semaphore(20)
    private val editPreparationSlots = java.util.concurrent.Semaphore(4)
    private val store by lazy {
        FileBrowserStore(FileBrowserDatabase.create(requireNotNull(context)))
    }
    private val transfers by lazy { TransferManager(requireNotNull(context), store) }
    private val writeAccess by lazy { DocumentWriteAccess(requireNotNull(context), store) }
    private val folders by lazy { ProviderFolderOperations(requireNotNull(context), store) }
    private val freshness by lazy {
        eu.opencloud.android.next.core.sync
            .ExternalFileFreshness(requireNotNull(context), store)
    }
    private val sharedFiles by lazy { SharedProviderFiles(requireNotNull(context)) }
    private val sharedRoots by lazy { SharedRootRows.create(requireNotNull(context)) }

    override fun onCreate(): Boolean = true

    override fun queryRoots(projection: Array<out String>?): Cursor =
        databaseCall {
            MatrixCursor(projection ?: DEFAULT_ROOT_PROJECTION).apply {
                if (eu.opencloud.android.next.core.security
                        .AppLock(requireNotNull(context))
                        .canOpenDocuments()
                ) {
                    store.activeAccounts().forEach { account -> addRoot(account) }
                } else {
                    newRow()
                        .add(Root.COLUMN_ROOT_ID, "locked")
                        .add(Root.COLUMN_DOCUMENT_ID, "locked")
                        .add(Root.COLUMN_TITLE, "Raiun")
                        .add(Root.COLUMN_SUMMARY, "Unlock to browse files")
                        .add(Root.COLUMN_ICON, requireNotNull(context).applicationInfo.icon)
                        .add(Root.COLUMN_FLAGS, Root.FLAG_SUPPORTS_IS_CHILD or Root.FLAG_SUPPORTS_CREATE)
                        .add(Root.COLUMN_MIME_TYPES, "*/*")
                }
            }
        }

    override fun queryDocument(
        documentId: String,
        projection: Array<out String>?,
    ): Cursor =
        databaseCall {
            requireUnlocked()
            if (documentId ==
                "locked"
            ) {
                return@databaseCall MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION).apply {
                    addDirectory("locked", "Raiun")
                }
            }
            if (SharedCollectionId.recognizes(documentId)) {
                requireAvailable(DocumentId.Account(SharedCollectionId.decode(documentId).account))
                return@databaseCall MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION).apply {
                    addSharedCollection(SharedCollectionId.decode(documentId).account)
                }
            }
            if (SharedDocumentId.recognizes(documentId)) {
                return@databaseCall sharedFiles.query(documentId, projection ?: DEFAULT_DOCUMENT_PROJECTION)
            }
            requireAvailable(DocumentId.decode(documentId))
            MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION).apply {
                when (val id = DocumentId.decode(documentId)) {
                    is DocumentId.Account -> addAccount(requireNotNull(store.account(id.accountId)))
                    is DocumentId.Space -> addSpace(requireNotNull(store.space(id.accountId, id.spaceId)))
                    is DocumentId.Resource ->
                        addResource(
                            requireNotNull(store.resource(id.accountId, id.spaceId, id.resourceId)),
                        )
                }
            }
        }

    override fun queryChildDocuments(
        parentDocumentId: String,
        projection: Array<out String>?,
        sortOrder: String?,
    ): Cursor =
        databaseCall {
            requireUnlocked()
            if (parentDocumentId ==
                "locked"
            ) {
                return@databaseCall MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION).apply {
                    store.activeAccounts().forEach { addAccount(it) }
                }
            }
            if (SharedCollectionId.recognizes(parentDocumentId)) {
                val account = SharedCollectionId.decode(parentDocumentId).account
                requireAvailable(DocumentId.Account(account))
                return@databaseCall sharedRoots.query(account, projection ?: DEFAULT_DOCUMENT_PROJECTION)
            }
            if (SharedDocumentId.recognizes(parentDocumentId)) {
                return@databaseCall sharedFiles.children(parentDocumentId, projection ?: DEFAULT_DOCUMENT_PROJECTION)
            }
            val id = DocumentId.decode(parentDocumentId)
            requireAvailable(id)
            val columns = (projection ?: DEFAULT_DOCUMENT_PROJECTION).map { it }.toTypedArray()
            when (id) {
                is DocumentId.Account -> accountChildren(id.accountId, columns)
                is DocumentId.Space -> {
                    refreshProviderFolder(id.accountId, id.spaceId, null)
                    childCursor(id, id.accountId, id.spaceId, null, columns)
                }
                is DocumentId.Resource -> {
                    require(store.resource(id.accountId, id.spaceId, id.resourceId)?.kind == ResourceKind.FOLDER)
                    refreshProviderFolder(id.accountId, id.spaceId, id.resourceId)
                    childCursor(id, id.accountId, id.spaceId, id.resourceId, columns)
                }
            }
        }

    @Suppress("LongParameterList") // Explicit document identity and projection define the provider query.
    private suspend fun childCursor(
        id: DocumentId,
        accountId: String,
        spaceId: String,
        parentId: String?,
        columns: Array<String>,
    ): Cursor =
        PagedDocumentCursor(columns, store.childCount(accountId, spaceId, parentId)) { offset ->
            databaseCall {
                requireAvailable(id)
                store.childrenPage(accountId, spaceId, parentId, offset).map { resource ->
                    columns.map { column -> resource.documentColumn(column) }.toTypedArray()
                }
            }
        }

    private fun ResourceEntity.documentColumn(column: String): Any? =
        when (column) {
            Document.COLUMN_DOCUMENT_ID -> DocumentId.Resource(accountId, spaceId, remoteId).encode()
            Document.COLUMN_DISPLAY_NAME -> name
            Document.COLUMN_MIME_TYPE -> documentMimeType()
            Document.COLUMN_SIZE -> sizeBytes
            Document.COLUMN_LAST_MODIFIED -> modifiedAtEpochMillis
            Document.COLUMN_FLAGS -> writeFlags(this)
            else -> null
        }

    override fun querySearchDocuments(
        rootId: String,
        query: String,
        projection: Array<out String>?,
    ): Cursor =
        databaseCall {
            requireUnlocked()
            if (rootId == "locked") return@databaseCall MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION)
            val account =
                DocumentId.decode(rootId) as? DocumentId.Account ?: throw FileNotFoundException("Invalid root.")
            requireAvailable(account)
            MatrixCursor(projection ?: DEFAULT_DOCUMENT_PROJECTION).apply {
                store.providerSearch(account.accountId, query).forEach { resource -> addResource(resource) }
            }
        }

    @Suppress("ReturnCount") // Separate editing, cached reads and asynchronous downloads own different descriptors.
    override fun openDocument(
        documentId: String,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        requireUnlocked()
        if (SharedCollectionId.recognizes(documentId)) unavailableSharedDocument()
        if (SharedDocumentId.recognizes(documentId)) {
            return databaseCall { sharedFiles.open(documentId, mode, signal) }
        }
        val readPermit =
            eu.opencloud.android.next.core.security
                .AppLock(requireNotNull(context))
                .beginDocumentRead()
        signal?.throwIfCanceled()
        val id = DocumentId.decode(documentId) as? DocumentId.Resource ?: throw FileNotFoundException("Not a file.")
        var resource =
            databaseCall {
                requireAvailable(id)
                store.resource(id.accountId, id.spaceId, id.resourceId)
            }
                ?: throw FileNotFoundException("Document not found.")
        require(resource.kind == ResourceKind.FILE) { "Folders cannot be opened as files." }
        if (mode != "r") return openForEdit(resource, mode, signal)
        resource = databaseCall { freshness.current(folders.settled(resource, readPermit), readPermit) }
        val cache = resourceCacheDirectory(requireNotNull(context).filesDir, id.accountId, id.spaceId)
        val localCopy =
            validatedCachedFile(cache, resource.localPath?.takeIf { resource.hasLocalCopy }, resource.sizeBytes)
        localCopy?.let { local ->
            return databaseCall {
                openCachedRead(local, openScope) {
                    signal?.throwIfCanceled()
                    requireAvailable(id, readPermit)
                    val current = store.resource(id.accountId, id.spaceId, id.resourceId)
                    if (current?.hasLocalCopy != true) throw FileNotFoundException("The local copy was removed.")
                    if (current.localPath != resource.localPath ||
                        current.eTag != resource.eTag ||
                        current.sizeBytes != resource.sizeBytes
                    ) {
                        throw FileNotFoundException("The local copy changed.")
                    }
                    if (validatedCachedFile(cache, current.localPath, current.sizeBytes) != local) {
                        throw FileNotFoundException("The local copy is unavailable.")
                    }
                }
            }
        }
        signal?.throwIfCanceled()
        if (!openSlots.tryAcquire()) throw FileNotFoundException("Too many documents are currently opening.")
        return openAfterDownload(id, resource, signal, readPermit)
    }

    private fun openForEdit(
        resource: ResourceEntity,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        val permit =
            eu.opencloud.android.next.core.security
                .AppLock(requireNotNull(context))
                .beginDocumentEdit()
        writeAccessMode(mode) // Reject unsupported modes before starting any transfer.
        if (!editPreparationSlots.tryAcquire()) throw FileNotFoundException("Too many documents are currently opening.")
        try {
            return databaseCall {
                ProviderFolderOperations.namespaceGate.withLock {
                    val current = freshness.current(folders.settled(resource, permit), permit)
                    val original = prepareEdit(current, permit, signal)
                    DocumentWriteSession(
                        eu.opencloud.android.next.core.sync
                            .DocumentEditStore(requireNotNull(context)),
                        openScope,
                        authorized = { writeAccess.authorized(current, permit) },
                    ).open(current, original, mode, signal)
                }
            }
        } finally {
            editPreparationSlots.release()
        }
    }

    private suspend fun prepareEdit(
        resource: ResourceEntity,
        permit: () -> Boolean,
        signal: CancellationSignal?,
    ): java.io.File {
        val preparation = currentCoroutineContext().job
        signal?.setOnCancelListener { preparation.cancel() }
        try {
            return withTimeout(30 * 60 * 1000L) {
                currentCoroutineContext().ensureActive()
                writeAccess.prepare(resource, permit) { downloadForEdit(it, permit) }
            }
        } finally {
            signal?.setOnCancelListener(null) // The descriptor adapter owns cancellation after preparation.
        }
    }

    private suspend fun downloadForEdit(
        resource: ResourceEntity,
        permit: () -> Boolean,
    ) {
        val transferId = transfers.enqueueDownload(resource, offlinePin = false)
        var completed = false
        while (!completed) {
            currentCoroutineContext().ensureActive()
            check(writeAccess.authorized(resource, permit)) { "Document editing is unavailable or locked." }
            val transfer = store.transfer(transferId) ?: throw FileNotFoundException("Download unavailable.")
            completed = transfer.state == "SUCCEEDED"
            if (!completed) {
                if (transfer.state !in setOf("QUEUED", "RUNNING", "RETRY")) {
                    throw FileNotFoundException("The document download did not complete.")
                }
                delay(250)
            }
        }
    }

    private fun writeFlags(resource: ResourceEntity): Int =
        if (resource.kind == ResourceKind.FOLDER) {
            Document.FLAG_DIR_SUPPORTS_CREATE
        } else if (writeAccess.editable(resource)) {
            Document.FLAG_SUPPORTS_WRITE or Document.FLAG_SUPPORTS_RENAME or Document.FLAG_SUPPORTS_DELETE
        } else {
            0
        }

    private val mutations by lazy {
        ProviderMutations(requireNotNull(context), store, folders, ::requireUnlocked) { requireAvailable(it) }
    }

    override fun createDocument(
        parentDocumentId: String,
        mimeType: String,
        displayName: String,
    ): String = mutations.createDocument(parentDocumentId, mimeType, displayName)

    override fun renameDocument(
        documentId: String,
        displayName: String,
    ): String = mutations.renameDocument(documentId, displayName)

    override fun deleteDocument(documentId: String) {
        mutations.deleteDocument(documentId)
        revokeDocumentPermission(documentId)
    }

    private fun documentPermit(): () -> Boolean =
        eu.opencloud.android.next.core.security
            .AppLock(requireNotNull(context))
            .beginDocumentEdit()

    // Failed discovery preserves cached browsing; mutations perform their own strict checks.
    @Suppress("TooGenericExceptionCaught")
    private suspend fun refreshProviderFolder(
        account: String,
        space: String,
        parent: String?,
    ) {
        try {
            folders.refresh(account, space, parent, documentPermit())
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            requireUnlocked()
        }
    }

    // Pipe errors are local; cancellation still escapes unchanged.
    @Suppress("TooGenericExceptionCaught", "ThrowsCount")
    private fun openAfterDownload(
        id: DocumentId.Resource,
        resource: ResourceEntity,
        signal: CancellationSignal?,
        readPermit: () -> Boolean,
    ): ParcelFileDescriptor {
        val pipe =
            try {
                ParcelFileDescriptor.createReliablePipe()
            } catch (failure: java.io.IOException) {
                openSlots.release()
                throw failure
            }
        val job =
            openScope.launch {
                try {
                    withTimeout(30 * 60 * 1000L) {
                        val transferId = transfers.enqueueDownload(resource, offlinePin = false)
                        store.observeTransfers(id.accountId).first { values ->
                            val transfer = values.find { it.id == transferId }
                            transfer == null || transfer.state !in setOf("QUEUED", "RUNNING", "RETRY")
                        }
                        requireAvailable(id, readPermit)
                        val current = requireNotNull(store.resource(id.accountId, id.spaceId, id.resourceId))
                        val directory =
                            resourceCacheDirectory(requireNotNull(context).filesDir, id.accountId, id.spaceId)
                        val file =
                            validatedCachedFile(
                                directory,
                                current.localPath?.takeIf { current.hasLocalCopy },
                                current.sizeBytes,
                            )
                                ?: throw FileNotFoundException("Download did not complete.")
                        val lease =
                            eu.opencloud.android.next.core.sync.LocalCopyLease
                                .acquire(file)
                        try {
                            requireAvailable(id, readPermit)
                            file.setLastModified(System.currentTimeMillis())
                            ParcelFileDescriptor.AutoCloseOutputStream(pipe[1]).use { output ->
                                file.inputStream().use { it.copyTo(output) }
                            }
                        } finally {
                            lease.close()
                        }
                    }
                } catch (cancelled: CancellationException) {
                    pipe[1].closeSafely("The document open was cancelled.")
                    throw cancelled
                } catch (_: Exception) {
                    pipe[1].closeSafely("The document could not be opened.")
                } finally {
                    try {
                        pipe[1].closeSafely(null)
                    } finally {
                        openSlots.release()
                    }
                }
            }
        val deadline =
            openScope.launch {
                delay(30 * 60 * 1000L)
                try {
                    pipe[1].closeSafely("The document open timed out.")
                } finally {
                    job.cancel()
                }
            }
        job.invokeOnCompletion { deadline.cancel() }
        signal?.setOnCancelListener {
            job.cancel()
            pipe[1].closeSafely("The document open was cancelled.")
        }
        return pipe[0]
    }

    private fun ParcelFileDescriptor.closeSafely(message: String?) {
        try {
            if (message == null) close() else closeWithError(message)
        } catch (_: java.io.IOException) {
            // The reader may already have closed the pipe; cleanup must preserve cancellation.
        }
    }

    override fun getDocumentType(documentId: String): String =
        databaseCall {
            requireUnlocked()
            if (documentId == "locked") return@databaseCall Document.MIME_TYPE_DIR
            if (SharedCollectionId.recognizes(documentId)) {
                requireAvailable(DocumentId.Account(SharedCollectionId.decode(documentId).account))
                return@databaseCall Document.MIME_TYPE_DIR
            }
            if (SharedDocumentId.recognizes(documentId)) {
                return@databaseCall sharedFiles.query(documentId, arrayOf(Document.COLUMN_MIME_TYPE)).use {
                    if (!it.moveToFirst()) unavailableSharedDocument()
                    it.getString(0)
                }
            }
            requireAvailable(DocumentId.decode(documentId))
            when (val id = DocumentId.decode(documentId)) {
                is DocumentId.Account, is DocumentId.Space -> Document.MIME_TYPE_DIR
                is DocumentId.Resource ->
                    store.resource(id.accountId, id.spaceId, id.resourceId)?.documentMimeType()
                        ?: throw FileNotFoundException("Document not found.")
            }
        }

    override fun isChildDocument(
        parentDocumentId: String,
        documentId: String,
    ): Boolean =
        databaseCall {
            requireUnlocked()
            sharedChildRelation(parentDocumentId, documentId)?.let { return@databaseCall it }
            if (parentDocumentId == "locked") {
                requireAvailable(DocumentId.decode(documentId))
                return@databaseCall true
            }
            val parent = DocumentId.decode(parentDocumentId)
            val child = DocumentId.decode(documentId)
            requireAvailable(parent)
            requireAvailable(child)
            when {
                parent is DocumentId.Account && child is DocumentId.Space -> parent.accountId == child.accountId
                parent is DocumentId.Account && child is DocumentId.Resource -> parent.accountId == child.accountId
                parent is DocumentId.Space && child is DocumentId.Resource ->
                    parent.accountId == child.accountId && parent.spaceId == child.spaceId
                parent is DocumentId.Resource && child is DocumentId.Resource -> isResourceChild(parent, child)
                else -> false
            }
        }

    private suspend fun sharedChildRelation(
        parent: String,
        child: String,
    ): Boolean? {
        // Navigation collections cannot grant access to all current and future incoming shares.
        if (SharedCollectionId.recognizes(parent) || SharedCollectionId.recognizes(child)) return false
        return sharedFiles.childRelation(parent, child)
    }

    private suspend fun accountChildren(
        account: String,
        columns: Array<String>,
    ): Cursor =
        MatrixCursor(columns).apply {
            store.spaces(account).filter { it.isPickerSpace() }.forEach { addSpace(it) }
            addSharedCollection(account)
        }

    private suspend fun isResourceChild(
        parent: DocumentId.Resource,
        child: DocumentId.Resource,
    ): Boolean {
        val sameSpace = parent.accountId == child.accountId && parent.spaceId == child.spaceId
        val folder =
            if (sameSpace && parent.resourceId != child.resourceId) {
                store.resource(parent.accountId, parent.spaceId, parent.resourceId)
            } else {
                null
            }
        if (folder?.kind != ResourceKind.FOLDER) return false
        var current = store.resource(child.accountId, child.spaceId, child.resourceId)
        var isChild = false
        val visited = mutableSetOf<String>()
        while (current?.parentId != null && !isChild && visited.size < 256) {
            val parentId = requireNotNull(current.parentId)
            if (!visited.add(parentId)) break
            isChild = parentId == parent.resourceId
            if (!isChild) current = store.resource(child.accountId, child.spaceId, parentId)
        }
        return isChild
    }

    private suspend fun requireAvailable(
        id: DocumentId,
        readPermit: (() -> Boolean)? = null,
    ) {
        if (readPermit == null) {
            requireUnlocked()
        } else if (!readPermit()) {
            throw FileNotFoundException("Document access was locked.")
        }
        val accountId =
            when (id) {
                is DocumentId.Account -> id.accountId
                is DocumentId.Space -> id.accountId
                is DocumentId.Resource -> id.accountId
            }
        requireVisible(store.account(accountId)?.isActive == true)
        val spaceId =
            when (id) {
                is DocumentId.Account -> null
                is DocumentId.Space -> id.spaceId
                is DocumentId.Resource -> id.spaceId
            }
        if (spaceId != null) {
            val space = store.space(accountId, spaceId)
            requireVisible(space != null && !space.isDisabled && !space.isDeleted)
        }
        if (id is DocumentId.Resource && store.resource(accountId, id.spaceId, id.resourceId) == null) {
            requireVisible(false)
        }
    }

    private fun requireVisible(available: Boolean) {
        if (!available) throw FileNotFoundException("Document unavailable.")
    }

    private fun MatrixCursor.addRoot(account: AccountEntity) {
        newRow()
            .add(Root.COLUMN_ROOT_ID, DocumentId.Account(account.id).encode())
            .add(Root.COLUMN_DOCUMENT_ID, DocumentId.Account(account.id).encode())
            .add(Root.COLUMN_TITLE, "Raiun")
            .add(Root.COLUMN_ICON, requireNotNull(context).applicationInfo.icon)
            .add(Root.COLUMN_SUMMARY, "${account.displayName} · ${android.net.Uri.parse(account.serverUrl).host}")
            .add(
                Root.COLUMN_FLAGS,
                Root.FLAG_SUPPORTS_SEARCH or Root.FLAG_SUPPORTS_IS_CHILD or Root.FLAG_SUPPORTS_CREATE,
            ).add(Root.COLUMN_MIME_TYPES, "*/*")
    }

    private fun MatrixCursor.addAccount(account: AccountEntity) {
        addDirectory(
            DocumentId.Account(account.id).encode(),
            account.displayName,
            Document.FLAG_DIR_BLOCKS_OPEN_DOCUMENT_TREE,
        )
    }

    private fun MatrixCursor.addSharedCollection(account: String) {
        val values =
            mapOf<String, Any?>(
                Document.COLUMN_DOCUMENT_ID to SharedCollectionId(account).encode(),
                Document.COLUMN_DISPLAY_NAME to "Shared with me",
                Document.COLUMN_MIME_TYPE to Document.MIME_TYPE_DIR,
                Document.COLUMN_FLAGS to Document.FLAG_DIR_BLOCKS_OPEN_DOCUMENT_TREE,
            )
        addRow(columnNames.map { values[it] }.toTypedArray())
    }

    private fun MatrixCursor.addSpace(space: SpaceEntity) {
        addDirectory(
            DocumentId.Space(space.accountId, space.driveId).encode(),
            if (space.type ==
                "personal"
            ) {
                "Personal files"
            } else {
                space.name
            },
            Document.FLAG_DIR_SUPPORTS_CREATE,
        )
    }

    private fun MatrixCursor.addResource(resource: ResourceEntity) {
        newRow()
            .add(
                Document.COLUMN_DOCUMENT_ID,
                DocumentId.Resource(resource.accountId, resource.spaceId, resource.remoteId).encode(),
            ).add(Document.COLUMN_DISPLAY_NAME, resource.name)
            .add(Document.COLUMN_MIME_TYPE, resource.documentMimeType())
            .add(Document.COLUMN_SIZE, resource.sizeBytes)
            .add(Document.COLUMN_LAST_MODIFIED, resource.modifiedAtEpochMillis)
            .add(Document.COLUMN_FLAGS, writeFlags(resource))
    }

    private fun MatrixCursor.addDirectory(
        id: String,
        name: String,
        flags: Int = Document.FLAG_DIR_BLOCKS_OPEN_DOCUMENT_TREE,
    ) {
        newRow()
            .add(Document.COLUMN_DOCUMENT_ID, id)
            .add(Document.COLUMN_DISPLAY_NAME, name)
            .add(Document.COLUMN_MIME_TYPE, Document.MIME_TYPE_DIR)
            .add(Document.COLUMN_FLAGS, flags)
    }

    private fun requireUnlocked() {
        val context = requireNotNull(context)
        if (!eu.opencloud.android.next.core.security
                .AppLock(context)
                .canOpenDocuments()
        ) {
            val intent =
                android.content.Intent().setClassName(
                    context.packageName,
                    eu.opencloud.android.next.core.security.AppLock.AUTH_ACTIVITY,
                )
            val action =
                android.app.PendingIntent.getActivity(
                    context,
                    0,
                    intent,
                    android.app.PendingIntent.FLAG_IMMUTABLE or android.app.PendingIntent.FLAG_UPDATE_CURRENT,
                )
            throw android.app.AuthenticationRequiredException(
                SecurityException("Unlock Raiun to access files."),
                action,
            )
        }
    }

    private fun <T> databaseCall(block: suspend () -> T): T = runBlocking { withContext(Dispatchers.IO) { block() } }

    private companion object {
        val DEFAULT_ROOT_PROJECTION =
            arrayOf(
                Root.COLUMN_ROOT_ID,
                Root.COLUMN_DOCUMENT_ID,
                Root.COLUMN_ICON,
                Root.COLUMN_TITLE,
                Root.COLUMN_SUMMARY,
                Root.COLUMN_FLAGS,
                Root.COLUMN_MIME_TYPES,
            )
        val DEFAULT_DOCUMENT_PROJECTION =
            arrayOf(
                Document.COLUMN_DOCUMENT_ID,
                Document.COLUMN_DISPLAY_NAME,
                Document.COLUMN_MIME_TYPE,
                Document.COLUMN_SIZE,
                Document.COLUMN_LAST_MODIFIED,
                Document.COLUMN_FLAGS,
            )
    }
}

// Incoming shares use their own checked catalog; virtual drives are server containers.
private fun SpaceEntity.isPickerSpace(): Boolean = !isDisabled && !isDeleted && type in setOf("personal", "project")

private fun ResourceEntity.documentMimeType() =
    if (kind == ResourceKind.FOLDER) {
        Document.MIME_TYPE_DIR
    } else {
        eu.opencloud.android.next.core.model
            .fileMimeType(name, mimeType)
    }
