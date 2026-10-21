package eu.opencloud.android.next.core.sync

import android.net.Uri

internal data class BackupDocument(
    val uri: Uri,
    val name: String,
    val relativeParent: String,
    val mimeType: String,
    val modified: Long,
    val size: Long,
)
