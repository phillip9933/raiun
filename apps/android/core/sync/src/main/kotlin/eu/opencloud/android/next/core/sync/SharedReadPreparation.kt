package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.AppLock
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withTimeout

/** Only absence/corruption of private bytes triggers downloading; denial/version changes never do. */
class SharedReadPreparation internal constructor(
    private val read: suspend () -> SharedReadSession,
    private val enqueue: suspend () -> String,
    private val state: suspend (String) -> String?,
    private val permitted: suspend () -> Boolean,
) {
    suspend fun open(): SharedReadSession {
        var pending: SharedReadSession? = null
        var delivered = false
        try {
            val session =
                withTimeout(30 * 60 * 1000L) {
                    requireAccess()
                    val opened =
                        try {
                            read()
                        } catch (_: SharedCopyUnavailable) {
                            download()
                            read()
                        }
                    pending = opened
                    requireAccess()
                    opened
                }
            delivered = true
            return session
        } finally {
            if (!delivered) pending?.close()
        }
    }

    private suspend fun download() {
        requireAccess()
        val id = enqueue()
        var completed = false
        while (!completed) {
            requireAccess()
            val current = state(id)
            completed = current == "SUCCEEDED"
            if (!completed) {
                if (current !in setOf("QUEUED", "RUNNING", "RETRY")) {
                    throw OpenCloudException(OpenCloudError.SourceUnavailable)
                }
                delay(250)
            }
        }
    }

    private suspend fun requireAccess() {
        currentCoroutineContext().ensureActive()
        if (!permitted()) throw OpenCloudException(OpenCloudError.AccessDenied)
    }

    companion object {
        suspend fun open(
            context: Context,
            request: SharedDownloadRequest,
        ): SharedReadSession {
            val app = context.applicationContext
            val permit = AppLock(app).beginDocumentRead()
            val resolver = SharedDownloadResolver.create(app)
            val source = resolver.prepare(request)
            val reader = SharedLocalReader.create(app)
            val database = FileBrowserDatabase.create(app)
            return SharedReadPreparation(
                { reader.open(request) },
                { TransferManager(app).enqueueSharedDownload(request, offlinePin = false).id },
                { id ->
                    database
                        .transferDao()
                        .findById(id)
                        ?.takeIf {
                            it.accountId == request.accountId &&
                                it.spaceId == request.scopeId &&
                                it.resourceId == request.file.remoteId &&
                                it.locationKind == "SHARED_FOLDER"
                        }?.state
                },
                { resolver.isCurrent(source) && permit() },
            ).open()
        }
    }
}
