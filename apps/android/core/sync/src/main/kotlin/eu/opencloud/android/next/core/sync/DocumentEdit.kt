package eu.opencloud.android.next.core.sync

/** OPEN and REVIEW drafts must never be submitted automatically after a process restart. */
enum class DocumentEditState { OPEN, REVIEW, READY, SUBMITTED }

data class DocumentEditInventory(
    val edits: List<DocumentEdit>,
    val unreadableCount: Int = 0,
)

data class DocumentEdit(
    val id: String,
    val accountId: String,
    val spaceId: String,
    val resourceId: String,
    val path: String,
    val name: String,
    val mimeType: String?,
    val baseETag: String,
    val state: DocumentEditState = DocumentEditState.OPEN,
    val sealedSize: Long = 0,
    val sealedSha256: String? = null,
)
