package eu.opencloud.android.next.feature.files

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.fileMimeType
import java.util.Base64

internal fun externalFileIntent(
    context: Context,
    resource: ResourceEntity,
): Intent {
    eu.opencloud.android.next.core.security
        .AppLock(context)
        .allowDocumentOpenFromApp()
    val id =
        Base64.getUrlEncoder().withoutPadding().encodeToString(
            listOf("v1", "resource", resource.accountId, resource.spaceId, resource.remoteId)
                .joinToString("\u0000")
                .toByteArray(Charsets.UTF_8),
        )
    val uri = DocumentsContract.buildDocumentUri("${context.packageName}.documents", id)
    val type = fileMimeType(resource.name, resource.mimeType)
    return Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, type)
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        clipData = ClipData.newRawUri(resource.name, uri)
    }
}

internal fun externalSendIntent(
    context: Context,
    resource: ResourceEntity,
): Intent {
    val open = externalFileIntent(context, resource)
    return Intent(Intent.ACTION_SEND).apply {
        type = open.type
        putExtra(Intent.EXTRA_STREAM, open.data)
        clipData = open.clipData
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
}
