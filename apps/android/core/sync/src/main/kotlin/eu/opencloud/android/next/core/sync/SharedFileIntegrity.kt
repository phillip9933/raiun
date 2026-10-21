package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.SharedFileCommit
import eu.opencloud.android.next.core.database.SharedLocalFile
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.network.ContentFingerprint
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.File

/** Checks private bytes only; server response/version checks and exclusive file ownership remain required. */
object SharedFileIntegrity {
    suspend fun inspect(
        directory: File,
        path: String,
        expectedSize: Long,
        completedAt: Long,
    ): SharedFileCommit =
        withContext(Dispatchers.IO) {
            val context = currentCoroutineContext()
            context.ensureActive()
            val file =
                validatedCachedFile(directory, path, expectedSize)
                    ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val fingerprint =
                file.inputStream().use { input ->
                    ContentFingerprint.read(input, expectedSize) { context.ensureActive() }
                }
            context.ensureActive()
            SharedFileCommit(file.path, fingerprint.length, fingerprint.sha256Hex(), completedAt)
        }

    suspend fun matches(
        directory: File,
        cached: SharedLocalFile,
    ): Boolean =
        withContext(Dispatchers.IO) {
            currentCoroutineContext().ensureActive()
            val file = validatedCachedFile(directory, cached.localPath, cached.sizeBytes) ?: return@withContext false
            inspect(directory, file.path, cached.sizeBytes, cached.downloadedAtEpochMillis).sha256 == cached.sha256
        }
}
