package eu.opencloud.android.next.core.model

/** A protocol-independent representation used by future file and DocumentsProvider features. */
data class Resource(
    val id: String,
    val name: String,
    val kind: ResourceKind,
    val metadata: String,
)

enum class ResourceKind {
    FOLDER,
    FILE,
}
