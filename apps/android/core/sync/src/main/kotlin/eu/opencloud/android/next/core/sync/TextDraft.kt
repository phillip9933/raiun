package eu.opencloud.android.next.core.sync

data class TextDraft(
    val accountId: String,
    val spaceId: String,
    val resourceId: String,
    val path: String,
    val name: String,
    val mimeType: String?,
    val baseETag: String,
    val text: String,
    val queuedId: String? = null,
)
