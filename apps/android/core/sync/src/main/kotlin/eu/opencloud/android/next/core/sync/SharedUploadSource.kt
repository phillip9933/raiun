package eu.opencloud.android.next.core.sync

import java.io.File

data class SharedUploadSource(
    val id: String,
    val name: String,
    val mimeType: String?,
    val payload: File,
    val expectedETag: String? = null,
    val resourceId: String? = null,
)
