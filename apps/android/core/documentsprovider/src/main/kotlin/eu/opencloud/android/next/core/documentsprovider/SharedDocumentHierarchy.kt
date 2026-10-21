package eu.opencloud.android.next.core.documentsprovider

internal class SharedHierarchyNode(
    val path: String,
    val folder: Boolean,
    val current: suspend () -> Boolean,
)

/** Resolution must use fresh server metadata; path containment alone never grants access. */
internal class SharedDocumentHierarchy(
    private val resolve: suspend (SharedDocumentId) -> SharedHierarchyNode,
    private val permit: () -> Boolean,
) {
    suspend fun isChild(
        parent: SharedDocumentId,
        child: SharedDocumentId,
    ): Boolean {
        val sameScope = parent.account == child.account && parent.share == child.share && parent.scope == child.scope
        if (!sameScope || parent.remote == child.remote) return false
        if (!permit()) unavailableSharedDocument()
        val folder = resolve(parent)
        val item = resolve(child)
        if (!folder.current() || !item.current() || !permit()) unavailableSharedDocument()
        val prefix = if (folder.path == "/") "/" else folder.path + "/"
        return folder.folder && item.path != folder.path && item.path.startsWith(prefix)
    }
}
