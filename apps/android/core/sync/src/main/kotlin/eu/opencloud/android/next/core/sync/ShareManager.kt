package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ShareEntity
import eu.opencloud.android.next.core.network.CreateShareRequest
import eu.opencloud.android.next.core.network.OcsShareType
import eu.opencloud.android.next.core.network.OcsSharingClient
import eu.opencloud.android.next.core.network.RemoteShare
import eu.opencloud.android.next.core.network.ShareRecipient
import eu.opencloud.android.next.core.network.UpdateShareRequest
import eu.opencloud.android.next.core.security.TlsPolicy
import okhttp3.OkHttpClient

class ShareManager(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
) {
    fun observe(accountId: String) = store.observeShares(accountId)

    suspend fun refresh(accountId: String) {
        val session = session(accountId)
        val owned = session.client.listShares(session.account.serverUrl, session.authorization)
        val received = session.client.listShares(session.account.serverUrl, session.authorization, sharedWithMe = true)
        store.replaceShares(
            accountId,
            owned.map { it.toEntity(accountId, false) } + received.map { it.toEntity(accountId, true) },
        )
    }

    suspend fun sharesForResource(
        accountId: String,
        path: String,
        resourceId: String? = null,
    ): List<ShareEntity> {
        val session = session(accountId)
        return session.client
            .listShares(
                session.account.serverUrl,
                session.authorization,
                path = path,
                resourceId = resourceId,
            ).map {
                it.toEntity(accountId, false)
            }
    }

    suspend fun publicLink(
        accountId: String,
        shareId: String,
    ): TransientPublicLink {
        val session = session(accountId)
        val link =
            session.client
                .listShares(session.account.serverUrl, session.authorization)
                .firstOrNull { it.id == shareId && it.type == OcsShareType.PUBLIC_LINK }
                ?.publicUrl
        require(!link.isNullOrBlank()) { "The public link is unavailable." }
        return TransientPublicLink(link)
    }

    suspend fun searchRecipients(
        accountId: String,
        query: String,
    ): List<ShareRecipient> {
        val session = session(accountId)
        return session.client.searchRecipients(session.account.serverUrl, session.authorization, query)
    }

    suspend fun create(
        accountId: String,
        request: CreateShareRequest,
    ): CreatedShare {
        val session = session(accountId)
        if (request.type == OcsShareType.PUBLIC_LINK) {
            require(session.account.publicSharingEnabled) { "Public link sharing is not supported by this server." }
            validatePublicLinkPolicy(session.account, request.password, request.expirationDate)
        }
        val remote =
            session.client
                .createShare(session.account.serverUrl, session.authorization, request)
        val confirmed = remote.toEntity(accountId, false)
        store.saveConfirmedShare(confirmed)
        return CreatedShare(confirmed, remote.publicUrl?.let(::TransientPublicLink))
    }

    suspend fun update(
        accountId: String,
        shareId: String,
        request: UpdateShareRequest,
    ) {
        val session = session(accountId)
        val share =
            session.client
                .listShares(session.account.serverUrl, session.authorization)
                .firstOrNull { it.id == shareId }
        requireNotNull(share) { "The share is unavailable." }
        if (share.type == OcsShareType.PUBLIC_LINK) {
            require(session.account.publicSharingEnabled) { "Public link sharing is not supported by this server." }
            val expiration =
                if (request.clearExpiration) {
                    null
                } else {
                    request.expirationDate
                        ?: share.expiresAtEpochMillis?.let {
                            java.time.Instant
                                .ofEpochMilli(it)
                                .atZone(java.time.ZoneOffset.UTC)
                                .toLocalDate()
                        }
                }
            validatePublicLinkPolicy(session.account, request.password, expiration, updating = true)
        }
        val updated = session.client.updateShare(session.account.serverUrl, session.authorization, shareId, request)
        store.saveConfirmedShare(updated.toEntity(accountId, false))
    }

    suspend fun revoke(
        accountId: String,
        shareId: String,
    ) {
        val session = session(accountId)
        session.client.revokeShare(session.account.serverUrl, session.authorization, shareId)
        store.deleteShare(accountId, shareId)
    }

    private suspend fun session(accountId: String): ShareSession {
        val account = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val capabilities = CapabilityRepository.get(context).refresh(account, authorization, store)
        require(capabilities.sharingEnabled) { "Sharing is not supported by this server." }
        val updatedAccount = requireNotNull(store.account(accountId)) { "The account is unavailable." }
        val http = TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl)
        return ShareSession(
            updatedAccount,
            authorization,
            OcsSharingClient(http) {
                CapabilityRepository.get(context).invalidate(accountId)
            },
        )
    }
}

class CreatedShare(
    val share: ShareEntity,
    val publicLink: TransientPublicLink?,
)

class TransientPublicLink internal constructor(
    private val value: String,
) {
    fun valueForClipboard(): String = value

    override fun toString(): String = "[REDACTED PUBLIC LINK]"
}

private data class ShareSession(
    val account: eu.opencloud.android.next.core.database.AccountEntity,
    val authorization: String,
    val client: OcsSharingClient,
)

private fun RemoteShare.toEntity(
    accountId: String,
    received: Boolean,
) = ShareEntity(
    accountId,
    id,
    resourceId,
    path,
    type.value,
    shareWith,
    displayName,
    additionalInfo,
    permissions,
    sharedAtEpochSeconds,
    expiresAtEpochMillis,
    label,
    isFolder,
    received,
)
