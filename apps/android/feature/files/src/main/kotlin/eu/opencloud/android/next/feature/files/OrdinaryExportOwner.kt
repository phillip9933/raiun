package eu.opencloud.android.next.feature.files

import android.content.Context
import android.net.Uri
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.TransferManager
import eu.opencloud.android.next.core.sync.exportCachedFile
import eu.opencloud.android.next.core.sync.prepareLocalResource
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Owns ordinary external-file preparation and one accepted export in the browser's scope.
 * Account authority and state reduction stay with the browser. Account changes hide an
 * old export's presentation, but do not release its gate or cancel admitted backend work.
 */
internal class OrdinaryExportOwner(
    private val scope: CoroutineScope,
    private val accountContext: BrowserAccountContext,
    private val files: OrdinaryExportFiles,
    private val reduce: (FileBrowserUiState.() -> FileBrowserUiState) -> Unit,
    private val mainDispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
) {
    private var exportInFlight = false

    suspend fun prepareExternalFile(resource: ResourceEntity): ResourceEntity {
        val binding =
            accountContext.admitResource(resource)
                ?: throw CancellationException("Resource account is no longer shown")
        val prepared = files.prepare(resource)
        withContext(mainDispatcher) {
            if (accountContext.binding != binding) throw CancellationException("Resource account is no longer shown")
        }
        return prepared
    }

    @Suppress("TooGenericExceptionCaught") // Keep a bounded status at the UI boundary; cancellation propagates.
    fun exportFile(
        spaceId: String,
        resourceId: String,
        destination: Uri,
        removeLocal: Boolean,
    ): Job? {
        val binding = accountContext.binding
        if (binding == null || exportInFlight) return null
        exportInFlight = true
        reduce { copy(exporting = true, exportStatus = "Preparing export…") }
        return scope.launch(Dispatchers.IO) {
            try {
                val resource = requireNotNull(files.resource(binding.accountId, spaceId, resourceId))
                val ready = files.prepare(resource)
                publish(binding) { copy(exportStatus = "Exporting ${ready.name}…") }
                files.export(ready, destination)
                if (removeLocal) files.removeLocalCopy(ready)
                publish(binding) {
                    copy(
                        exportStatus =
                            if (removeLocal) {
                                "Exported; app's local copy removed. Cloud file kept."
                            } else {
                                "Saved to the selected location."
                            },
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                publish(binding) {
                    copy(
                        exportStatus =
                            "Export did not finish. Your cloud file is unchanged. " +
                                "Check the destination before retrying.",
                    )
                }
            } finally {
                withContext(NonCancellable + mainDispatcher) {
                    exportInFlight = false
                    publish(binding) { copy(exporting = false) }
                }
            }
        }
    }

    private suspend fun publish(
        binding: BrowserAccountBinding,
        transform: FileBrowserUiState.() -> FileBrowserUiState,
    ) = accountContext.publishAccount(binding) { reduce(transform) }
}

/** Existing cache/provider operations; exporting verifies the destination before local-copy removal. */
internal interface OrdinaryExportFiles {
    suspend fun resource(
        account: String,
        space: String,
        id: String,
    ): ResourceEntity?

    suspend fun prepare(resource: ResourceEntity): ResourceEntity

    suspend fun export(
        resource: ResourceEntity,
        destination: Uri,
    )

    suspend fun removeLocalCopy(resource: ResourceEntity)
}

internal class AndroidOrdinaryExportFiles(
    private val context: Context,
    private val store: FileBrowserStore,
    private val transfers: TransferManager,
) : OrdinaryExportFiles {
    override suspend fun resource(
        account: String,
        space: String,
        id: String,
    ): ResourceEntity? = store.resource(account, space, id)

    override suspend fun prepare(resource: ResourceEntity): ResourceEntity = prepareLocalResource(context, resource)

    override suspend fun export(
        resource: ResourceEntity,
        destination: Uri,
    ) = exportCachedFile(context, resource, destination)

    override suspend fun removeLocalCopy(resource: ResourceEntity) {
        transfers.removeLocalCopy(resource, requireSameCopy = true)
    }
}
