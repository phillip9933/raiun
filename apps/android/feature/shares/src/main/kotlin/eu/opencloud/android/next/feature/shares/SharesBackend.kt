package eu.opencloud.android.next.feature.shares

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.ShareEntity
import eu.opencloud.android.next.core.network.CreateShareRequest
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.UpdateShareRequest
import eu.opencloud.android.next.core.sync.CreatedShare
import eu.opencloud.android.next.core.sync.ShareManager
import kotlinx.coroutines.flow.Flow

internal interface SharesBackend {
    suspend fun account(id: String): AccountEntity?

    fun observe(id: String): Flow<List<ShareEntity>>

    suspend fun refresh(id: String)

    suspend fun resourceShares(resource: ResourceEntity): List<ShareEntity>

    suspend fun recipients(
        id: String,
        query: String,
    ): List<ShareRecipient>

    suspend fun create(
        id: String,
        request: CreateShareRequest,
    ): CreatedShare

    suspend fun update(
        id: String,
        shareId: String,
        permissions: Int,
    )

    suspend fun revoke(
        id: String,
        shareId: String,
    )
}

internal class AndroidSharesBackend(
    context: Context,
) : SharesBackend {
    private val store = FileBrowserStore(FileBrowserDatabase.create(context))
    private val manager = ShareManager(context, store)

    override suspend fun account(id: String) = store.account(id)

    override fun observe(id: String) = manager.observe(id)

    override suspend fun refresh(id: String) = manager.refresh(id)

    override suspend fun resourceShares(resource: ResourceEntity) =
        manager.sharesForResource(resource.accountId, resource.path, resource.remoteId)

    override suspend fun recipients(
        id: String,
        query: String,
    ) = manager.searchRecipients(id, query)

    override suspend fun create(
        id: String,
        request: CreateShareRequest,
    ) = manager.create(id, request)

    override suspend fun update(
        id: String,
        shareId: String,
        permissions: Int,
    ) = manager.update(id, shareId, UpdateShareRequest(permissions = permissions))

    override suspend fun revoke(
        id: String,
        shareId: String,
    ) = manager.revoke(id, shareId)
}
