package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.VaultExclusion
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.network.RemoteSearchClient
import eu.opencloud.android.next.core.network.RemoteSearchResource
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import okhttp3.OkHttpClient

interface SearchRepository {
    fun search(
        accountId: String,
        query: String,
    ): Flow<SearchRepositoryResult>
}

fun createSearchRepository(
    context: Context,
    store: FileBrowserStore,
): SearchRepository {
    val database = FileBrowserDatabase.create(context)
    return RoomSearchRepository(
        store = store,
        accountProvider = store::account,
        exclusionFlow = database.vaultExclusionDao()::observe,
        remoteSearch = { account, query ->
            RemoteSearchClient(
                client = TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl),
            ).search(
                endpointUrl = requireNotNull(account.remoteSearchUrl),
                query = query,
                authorization = WorkerAuthorizationProvider(context).authorization(account),
                limit = REMOTE_SEARCH_RESULT_LIMIT + 1,
            )
        },
        errorMessage = { it.toOpenCloudError().safeMessage(context) },
    )
}

data class SearchRepositoryResult(
    val resources: List<ResourceEntity>,
    val remoteSupported: Boolean,
    val remoteLoading: Boolean = false,
    val remoteError: String? = null,
    val remoteResultsCapped: Boolean = false,
)

class RoomSearchRepository(
    private val localSearch: (String, String) -> Flow<List<ResourceEntity>>,
    private val accountProvider: suspend (String) -> AccountEntity?,
    private val remoteSearch: suspend (AccountEntity, String) -> List<RemoteSearchResource>,
    private val remoteDelayMillis: Long = REMOTE_DEBOUNCE_MILLIS,
    private val exclusionFlow: (String) -> Flow<List<VaultExclusion>> = { flowOf(emptyList()) },
    private val errorMessage: (Throwable) -> String = { it.toOpenCloudError().safeMessage() },
) : SearchRepository {
    constructor(
        store: FileBrowserStore,
        accountProvider: suspend (String) -> AccountEntity?,
        remoteSearch: suspend (AccountEntity, String) -> List<RemoteSearchResource>,
        remoteDelayMillis: Long = REMOTE_DEBOUNCE_MILLIS,
        exclusionFlow: (String) -> Flow<List<VaultExclusion>> = { flowOf(emptyList()) },
        errorMessage: (Throwable) -> String = { it.toOpenCloudError().safeMessage() },
    ) : this(store::searchResources, accountProvider, remoteSearch, remoteDelayMillis, exclusionFlow, errorMessage)

    override fun search(
        accountId: String,
        query: String,
    ): Flow<SearchRepositoryResult> {
        val normalized = query.trim()
        if (normalized.isBlank()) return flowOf(SearchRepositoryResult(emptyList(), remoteSupported = false))
        val local = localSearch(accountId, normalized)
        val exclusions = exclusionFlow(accountId)
        val remote =
            flow {
                emit(RemoteResult(supported = false))
                val account = accountProvider(accountId)
                val supported = account?.remoteSearchUrl != null
                emit(RemoteResult(supported = supported, loading = supported))
                if (!supported) return@flow
                delay(remoteDelayMillis)
                val fetched = remoteSearch(account, normalized)
                emit(
                    RemoteResult(
                        supported = true,
                        resources = fetched.take(REMOTE_SEARCH_RESULT_LIMIT),
                        capped = fetched.size > REMOTE_SEARCH_RESULT_LIMIT,
                    ),
                )
            }.catch { emit(RemoteResult(supported = true, error = errorMessage(it))) }
        return combine(local, remote, exclusions) { localResources, remoteResult, currentExclusions ->
            val merged = mergeSearchResults(localResources, remoteResult.resources, accountId)
            SearchRepositoryResult(
                resources =
                    merged.filterNot { resource ->
                        isVaultExcludedPath(accountId, resource.spaceId, resource.path, currentExclusions)
                    },
                remoteSupported = remoteResult.supported,
                remoteLoading = remoteResult.loading,
                remoteError = remoteResult.error,
                remoteResultsCapped = remoteResult.capped,
            )
        }
    }

    private data class RemoteResult(
        val supported: Boolean,
        val loading: Boolean = false,
        val resources: List<RemoteSearchResource> = emptyList(),
        val error: String? = null,
        val capped: Boolean = false,
    )
}

fun mergeSearchResults(
    local: List<ResourceEntity>,
    remote: List<RemoteSearchResource>,
    accountId: String,
): List<ResourceEntity> =
    (local + remote.map { it.toEntity(accountId) })
        .distinctBy { it.spaceId to it.remoteId }
        .sortedWith(
            compareBy<ResourceEntity> {
                it.kind != ResourceKind.FOLDER
            }.thenBy(String.CASE_INSENSITIVE_ORDER) { it.name },
        )

private fun RemoteSearchResource.toEntity(accountId: String) =
    ResourceEntity(
        accountId = accountId,
        spaceId = spaceId,
        remoteId = id,
        parentId = null,
        path = path,
        name = name,
        kind = if (folder) ResourceKind.FOLDER else ResourceKind.FILE,
        mimeType = mimeType,
        sizeBytes = size,
        eTag = eTag,
        modifiedAtEpochMillis = modifiedAtEpochMillis,
        createdAtEpochMillis = 0,
    )

private const val REMOTE_DEBOUNCE_MILLIS = 350L
private const val REMOTE_SEARCH_RESULT_LIMIT = 50
