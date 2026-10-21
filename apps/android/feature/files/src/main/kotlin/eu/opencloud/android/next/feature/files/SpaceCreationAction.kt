package eu.opencloud.android.next.feature.files

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.designsystem.localizedString
import eu.opencloud.android.next.core.network.LibreGraphSpacesClient
import eu.opencloud.android.next.core.security.TlsPolicy
import eu.opencloud.android.next.core.sync.PendingSpaceCreations
import eu.opencloud.android.next.core.sync.SpaceCreationResult
import eu.opencloud.android.next.core.sync.SpaceRepository
import eu.opencloud.android.next.core.sync.WorkerAuthorizationProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient

internal suspend fun createProjectSpace(
    context: Context,
    store: FileBrowserStore,
    accountId: String,
    name: String,
): SpaceCreationResult =
    withContext(Dispatchers.IO) {
        val account = requireNotNull(store.account(accountId))
        val http = TlsPolicy(context).applyTo(OkHttpClient(), account.serverUrl)
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        SpaceRepository(store, LibreGraphSpacesClient(http), PendingSpaceCreations(context))
            .createProjectSpace(accountId, account.serverUrl, authorization, name)
    }

internal fun SpaceCreationResult.AwaitingDiscovery.message(context: Context): String =
    context.localizedString(
        if (retrySafe) R.string.space_created_refresh_pending else R.string.space_created_recovery_not_saved,
    )
