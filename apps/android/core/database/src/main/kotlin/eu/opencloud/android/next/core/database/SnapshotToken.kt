package eu.opencloud.android.next.core.database

/** A refresh lease owned by one database instance. Network requests cannot survive process death. */
class SnapshotToken internal constructor(
    internal val accountId: String,
    internal val generation: String,
    internal val scope: FolderSnapshotScope? = null,
    internal val scopeGeneration: String? = null,
)

internal data class FolderSnapshotScope(
    val spaceId: String,
    val parentId: String?,
)

/** Access only inside this database's Room transactions. Mutations invalidate all account scopes. */
internal class SnapshotVersions {
    private val generations = mutableMapOf<String, String>()
    private val folders = mutableMapOf<Pair<String, FolderSnapshotScope>, String>()

    fun capture(accountId: String): SnapshotToken =
        SnapshotToken(
            accountId,
            generations.getOrPut(accountId) {
                java.util.UUID
                    .randomUUID()
                    .toString()
            },
        )

    fun isCurrent(token: SnapshotToken): Boolean = generations[token.accountId] == token.generation

    fun begin(accountId: String): SnapshotToken {
        val generation =
            java.util.UUID
                .randomUUID()
                .toString()
        generations[accountId] = generation
        folders.keys.removeAll { it.first == accountId }
        return SnapshotToken(accountId, generation)
    }

    fun beginFolder(
        accountId: String,
        scope: FolderSnapshotScope,
    ): SnapshotToken {
        val generation =
            generations.getOrPut(accountId) {
                java.util.UUID
                    .randomUUID()
                    .toString()
            }
        val scoped =
            java.util.UUID
                .randomUUID()
                .toString()
        folders[accountId to scope] = scoped
        // Failed requests may never publish. Eviction rejects their leases rather than retaining unbounded state.
        if (folders.size > MAX_FOLDER_LEASES) folders.remove(folders.keys.first())
        return SnapshotToken(accountId, generation, scope, scoped)
    }

    fun accept(
        accountId: String,
        token: SnapshotToken?,
        scope: FolderSnapshotScope? = null,
    ): Boolean {
        if (token != null && (token.accountId != accountId || generations[accountId] != token.generation)) return false
        return if (token?.scope != null) {
            val valid = token.scope == scope && folders[accountId to token.scope] == token.scopeGeneration
            if (valid) folders.remove(accountId to token.scope)
            valid
        } else {
            begin(accountId)
            true
        }
    }

    private companion object {
        const val MAX_FOLDER_LEASES = 1024
    }
}
