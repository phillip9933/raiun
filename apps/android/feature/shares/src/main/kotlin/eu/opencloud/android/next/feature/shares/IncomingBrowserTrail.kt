package eu.opencloud.android.next.feature.shares

import eu.opencloud.android.next.core.sync.SharedFolderRequest

/** Saved navigation is only a selection. Restoration always fetches fresh scope and folder evidence. */
internal object IncomingBrowserTrail {
    fun save(trail: List<IncomingBrowserItem.Folder>): List<String> =
        trail.flatMap {
            val request = it.request
            listOf(request.account, request.share, request.scope, request.remoteId, request.path, it.name)
        }

    fun restore(
        account: String,
        saved: List<String>,
    ): List<IncomingBrowserItem.Folder> {
        if (!validEncoding(saved)) {
            return emptyList()
        }
        val trail =
            saved.chunked(6).map {
                IncomingBrowserItem.Folder(it[5], SharedFolderRequest(it[0], it[1], it[2], it[3], it[4]))
            }
        val root = trail.firstOrNull()?.request
        val valid =
            trail.withIndex().all { (index, folder) ->
                val request = folder.request
                val bound = request.account == account && request.share == root?.share && request.scope == root?.scope
                bound && validPath(request.path, trail.getOrNull(index - 1)?.request?.path)
            }
        return if (valid) trail else emptyList()
    }

    private fun validEncoding(saved: List<String>): Boolean {
        val bounded = saved.size % 6 == 0 && saved.size <= 384
        return bounded && saved.all { it.isNotBlank() && it.length <= 4096 }
    }

    private fun validPath(
        path: String,
        previous: String?,
    ): Boolean {
        if (previous == null && path == "/") return true
        val segments = path.split('/').drop(1)
        val safe = path.startsWith('/') && segments.none(::invalidSegment)
        val parent = path.substringBeforeLast('/').ifEmpty { "/" }
        return safe && path != "/" && (previous == null || parent == previous)
    }

    private fun invalidSegment(value: String): Boolean {
        val special = value.isBlank() || value in setOf(".", "..")
        return special || value.any { it == '\\' || it.code < 32 || it.code == 127 }
    }
}
