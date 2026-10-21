package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/** Authorize the exact descendant using GET, without treating listing rights or HEAD as a content grant. */
internal suspend fun authorizeSharedContent(
    source: PreparedSharedDownload,
    client: TransferClient,
    authorization: String,
) = withContext(Dispatchers.IO) {
    // Cached bytes need a strong representation validator; weak/missing versions require a new download.
    if (source.expectation.strongETag == null) throw OpenCloudException(OpenCloudError.PreconditionFailed)
    withRequestCancellation(client::cancelRequests) {
        val context = currentCoroutineContext()
        client.download(source.url, authorization, 0, source.expectation) { _, _, _ ->
            // GET headers establish current content access and version. The reader verifies cached bytes separately.
            // Closing the response avoids downloading the full representation merely to reopen a verified copy.
            context.ensureActive()
        }
    }
    Unit
}
