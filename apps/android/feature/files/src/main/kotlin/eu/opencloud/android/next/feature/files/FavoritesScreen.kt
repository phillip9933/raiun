package eu.opencloud.android.next.feature.files

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.work.WorkInfo
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.DirectorySort
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceCollection
import eu.opencloud.android.next.core.database.ResourceCollectionOptions
import eu.opencloud.android.next.core.database.ResourceCollectionPaging
import eu.opencloud.android.next.core.database.ResourceCollectionRoot
import eu.opencloud.android.next.core.database.ResourceDirectoryPage
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.sync.AccountDiscoveryWorker
import eu.opencloud.android.next.core.sync.TransferManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class FavoritesUiState(
    val resources: List<ResourceEntity> = emptyList(),
    val page: ResourceDirectoryPage? = null,
    val keptOffline: List<ResourceEntity> = emptyList(),
    val error: String? = null,
    val syncStatus: FavoritesSyncStatus = FavoritesSyncStatus.IDLE,
    val refreshError: String? = null,
)

enum class FavoritesSyncStatus { IDLE, RUNNING, MORE, FAILED, UNAVAILABLE }

class FavoritesViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val transfers = TransferManager(application, store)
    private val mutableState = MutableStateFlow(FavoritesUiState())
    val state = mutableState.asStateFlow()
    private val paging = ResourceCollectionPaging(FileBrowserDatabase.create(application))
    private val pager =
        CachedCollectionPager(
            viewModelScope,
            paging::invalidations,
            { paging.load(it.account, ResourceCollection.Favorites, it.options) },
        )
    private var accountId: String? = null
    private var loadJob: Job? = null

    init {
        viewModelScope.launch(Dispatchers.IO) {
            pager.state.collectLatest { cached ->
                if (cached.request?.account == accountId) {
                    mutableState.update {
                        it.copy(
                            resources =
                                cached.result
                                    ?.page
                                    ?.entries
                                    ?.mapNotNull { row -> row.resource }
                                    .orEmpty(),
                            page = cached.result?.page,
                            keptOffline = cached.result?.keptOffline.orEmpty(),
                            error = cached.error?.toOpenCloudError()?.safeMessage(getApplication()),
                        )
                    }
                }
            }
        }
    }

    fun load(accountId: String) {
        if (this.accountId == accountId) return
        loadJob?.cancel()
        this.accountId = accountId
        mutableState.value = FavoritesUiState()
        pager.account(accountId)
        loadJob =
            viewModelScope.launch(Dispatchers.IO) {
                WorkManager
                    .getInstance(getApplication<Application>())
                    .getWorkInfosForUniqueWorkFlow("discover-$accountId")
                    .collectLatest { work ->
                        if (this@FavoritesViewModel.accountId == accountId) {
                            val info = work.singleOrNull()
                            mutableState.update {
                                it.copy(
                                    refreshError =
                                        info?.outputData?.getString(
                                            eu.opencloud.android.next.core.sync.DISCOVERY_ERROR,
                                        ),
                                    syncStatus =
                                        favoriteSyncStatus(
                                            info?.state,
                                            info?.outputData?.getInt(AccountDiscoveryWorker.FAVORITE_REMAINING, -1)
                                                ?: -1,
                                        ),
                                )
                            }
                        }
                    }
            }
    }

    fun display(
        query: String,
        sort: String,
        ascending: Boolean,
        showHidden: Boolean,
    ) {
        val criterion = DirectorySort.entries.firstOrNull { it.name == sort } ?: return
        pager.options(
            ResourceCollectionOptions(query = query, sort = criterion, ascending = ascending, showHidden = showHidden),
        )
    }

    fun knownRoots(roots: List<eu.opencloud.android.next.core.sync.VaultLocation>) =
        pager.roots(
            roots
                .filter {
                    it.accountId == accountId
                }.map { ResourceCollectionRoot(it.driveId, it.remoteVaultId, it.vaultPath) },
        )

    fun page(previous: Boolean) = pager.page(previous)

    fun refresh() {
        accountId?.let(transfers::refreshAccount)
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary retains cancellation and account isolation.
    fun remove(resource: ResourceEntity) {
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) { transfers.setFavorite(resource, false) }
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                if (resource.accountId == accountId) {
                    mutableState.update { it.copy(error = failure.toOpenCloudError().safeMessage(getApplication())) }
                }
            }
        }
    }

    fun dismissError() {
        mutableState.value = mutableState.value.copy(error = null)
    }
}

internal fun favoriteSyncStatus(
    state: WorkInfo.State?,
    remaining: Int,
): FavoritesSyncStatus =
    when {
        state == null -> FavoritesSyncStatus.IDLE
        !state.isFinished -> FavoritesSyncStatus.RUNNING
        state == WorkInfo.State.FAILED -> FavoritesSyncStatus.FAILED
        state != WorkInfo.State.SUCCEEDED -> FavoritesSyncStatus.IDLE
        remaining < 0 -> FavoritesSyncStatus.UNAVAILABLE
        remaining > 0 -> FavoritesSyncStatus.MORE
        else -> FavoritesSyncStatus.IDLE
    }
