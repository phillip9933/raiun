package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultOfflineGroupEntity
import eu.opencloud.android.next.core.database.VaultOfflineGroups
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.runBlocking

/** Admission survives scheduling/process death. Incomplete private preparation never authorizes publication. */
internal suspend fun reconcileVaultOfflineGroups(
    context: Context,
    store: FileBrowserStore,
    plans: VaultOfflineGroupPlanStore = VaultOfflineGroupPlanStore(context),
) {
    val coroutine = currentCoroutineContext()
    val groups = store.vaultOfflineGroups()
    for (account in store.activeAccounts()) {
        coroutine.ensureActive()
        val owner = groups.captureOwner(account.id) ?: continue
        cancelAbandonedGroupPreparations(groups, plans, owner)
        plans.reconcile(owner) { id ->
            coroutine.ensureActive()
            runBlocking {
                if (!groups.isCurrentOwner(owner) || groups.hasUnresolved(owner, id)) {
                    true // Revoked/uncertain authority never authorizes a sweep.
                } else {
                    val retained = groups.find(id)
                    retained?.parent != null && retained.group.state != "SUCCEEDED"
                }
            }
        }
    }
}

private suspend fun cancelAbandonedGroupPreparations(
    groups: VaultOfflineGroups,
    plans: VaultOfflineGroupPlanStore,
    owner: VaultGroupOwner,
) {
    var after: String? = null
    while (true) {
        currentCoroutineContext().ensureActive()
        val page = groups.groupPage(owner, after)
        if (page.isEmpty()) break
        for (group in page) cancelAbandonedGroupPreparation(groups, plans, owner, group)
        after = page.last().id
    }
}

private suspend fun cancelAbandonedGroupPreparation(
    groups: VaultOfflineGroups,
    plans: VaultOfflineGroupPlanStore,
    owner: VaultGroupOwner,
    group: VaultOfflineGroupEntity,
) {
    val abandoned =
        group.state == "PREPARING" &&
            !plans.hasActivePreparation(owner, group.id) &&
            !groups.hasUnresolved(owner, group.id)
    if (abandoned) {
        val expected = groups.find(group.id)
        if (expected?.group == group && expected.parent == null) groups.cancel(expected, System.currentTimeMillis())
    }
}
