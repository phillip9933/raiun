package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.VaultExclusion
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

/** Discover real parent identities through normal folder listings; never insert synthetic favorite rows. */
internal class FavoriteHydrator(
    private val store: FileBrowserStore,
    private val isVaultExcluded: suspend (String, String, String) -> Boolean = { _, _, _ -> false },
    private val currentExclusions: suspend (String) -> List<VaultExclusion> = { emptyList() },
    private val refresh: suspend (spaceId: String, parentId: String?, path: String) -> Unit,
) {
    suspend fun hydrate(
        accountId: String,
        locations: Map<String, Map<String, String>>,
        requestBudget: Int = 32,
        itemBudget: Int = 256,
    ): Int {
        require(requestBudget in 1..128)
        require(itemBudget in 1..1024)
        val visited = mutableSetOf<Pair<String, String?>>()
        val targets =
            locations
                .flatMap { (space, items) -> items.map { (id, path) -> Target(accountId, space, id, path) } }
                .sortedWith(compareBy(Target::spaceId, Target::resourceId))
        var cursor = store.favoriteCursor(accountId)
        val startingCursor = cursor
        val start =
            targets
                .indexOfFirst { target ->
                    startingCursor == null ||
                        target.spaceId > startingCursor.spaceId ||
                        (target.spaceId == startingCursor.spaceId && target.resourceId > startingCursor.resourceId)
                }.coerceAtLeast(0)
        val unresolved = mutableListOf<Target>()
        var processed = 0
        while (processed < targets.size && processed < itemBudget && visited.size < requestBudget) {
            currentCoroutineContext().ensureActive()
            val target = targets[(start + processed) % targets.size]
            unresolvedTarget(target, visited, requestBudget)?.let(unresolved::add)
            cursor = store.advanceFavoriteCursor(accountId, target.spaceId, target.resourceId, cursor)
                ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            processed++
        }
        val remaining = unresolved + unprocessedTargets(targets, start, processed)
        return countAllowed(accountId, remaining)
    }

    private suspend fun unresolvedTarget(
        target: Target,
        visited: MutableSet<Pair<String, String?>>,
        requestBudget: Int,
    ): Target? =
        when {
            isVaultExcluded(target.accountId, target.spaceId, target.path) -> null
            store.resource(target.accountId, target.spaceId, target.resourceId)?.path == target.path -> null
            discover(target, visited, requestBudget) -> null
            else -> target
        }

    private fun unprocessedTargets(
        targets: List<Target>,
        start: Int,
        processed: Int,
    ): List<Target> =
        (processed until targets.size).map { offset ->
            targets[(start + offset) % targets.size]
        }

    private suspend fun countAllowed(
        accountId: String,
        targets: List<Target>,
    ): Int {
        val exclusions = currentExclusions(accountId)
        return targets.count { target -> !isVaultExcludedPath(accountId, target.spaceId, target.path, exclusions) }
    }

    private suspend fun discover(
        target: Target,
        visited: MutableSet<Pair<String, String?>>,
        budget: Int,
    ): Boolean {
        var parentId: String? = null
        var parentPath = "/"
        var found = false
        val segments =
            target.path
                .trim('/')
                .split('/')
                .filter(String::isNotEmpty)
        for ((index, segment) in segments.withIndex()) {
            val key = target.spaceId to parentId
            var child = store.child(target.accountId, target.spaceId, parentId, segment)
            val wrongIdentity = index == segments.lastIndex && child?.remoteId != target.resourceId
            val expectedPath = "${parentPath.trimEnd('/')}/$segment"
            val stale = child?.path != expectedPath || wrongIdentity
            if (stale && key !in visited) {
                if (visited.size >= budget) return false
                visited.add(key)
                refresh(target.spaceId, parentId, parentPath)
                child = store.child(target.accountId, target.spaceId, parentId, segment)
            }
            found = index == segments.lastIndex && child?.remoteId == target.resourceId && child.path == target.path
            if (index == segments.lastIndex || child?.kind != ResourceKind.FOLDER) break
            parentId = child.remoteId
            parentPath = child.path
        }
        return found
    }

    private data class Target(
        val accountId: String,
        val spaceId: String,
        val resourceId: String,
        val path: String,
    )
}

internal fun filterFavoriteLocations(
    accountId: String,
    locations: Map<String, Map<String, String>>,
    exclusions: List<VaultExclusion>,
): Map<String, Map<String, String>> =
    locations.mapValues { (spaceId, items) ->
        items.filterValues { path -> !isVaultExcludedPath(accountId, spaceId, path, exclusions) }
    }

internal fun isVaultExcludedPath(
    accountId: String,
    spaceId: String,
    path: String,
    exclusions: List<VaultExclusion>,
): Boolean =
    exclusions.any { exclusion ->
        if (accountId != exclusion.accountId || spaceId != exclusion.spaceId) {
            false
        } else {
            val excludedPath = exclusion.path.trimEnd('/')
            excludedPath.isEmpty() ||
                path == excludedPath ||
                path.startsWith("$excludedPath/")
        }
    }
