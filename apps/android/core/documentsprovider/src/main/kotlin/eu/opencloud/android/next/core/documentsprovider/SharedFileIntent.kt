package eu.opencloud.android.next.core.documentsprovider

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.sync.SharedDownloadRequest

/** Shares only a scoped provider URI. Content authorization is performed again by the provider on open. */
fun sharedFileViewIntent(
    context: Context,
    request: SharedDownloadRequest,
    mimeType: String,
): Intent {
    val id = SharedDocumentId(request.accountId, request.shareId, request.scopeId, request.file.remoteId).encode()
    val uri = DocumentsContract.buildDocumentUri("${context.packageName}.documents", id)
    return Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, mimeType)
        clipData = ClipData.newRawUri("Shared file", uri)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
}
