package eu.opencloud.android.next.feature.files

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.work.WorkInfo
import androidx.work.WorkManager
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
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
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class FavoritesUiState(
    val resources: List<ResourceEntity> = emptyList(),
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
    private var accountId: String? = null
    private var loadJob: Job? = null

    fun load(accountId: String) {
        if (this.accountId == accountId) return
        loadJob?.cancel()
        this.accountId = accountId
        mutableState.value = FavoritesUiState()
        loadJob =
            viewModelScope.launch(Dispatchers.IO) {
                store
                    .observeFavorites(accountId)
                    .combine(
                        WorkManager
                            .getInstance(
                                getApplication<Application>(),
                            ).getWorkInfosForUniqueWorkFlow("discover-$accountId"),
                    ) { resources, work ->
                        val info = work.singleOrNull()
                        mutableState.value.copy(
                            resources = resources,
                            refreshError =
                                info?.outputData?.getString(
                                    eu.opencloud.android.next.core.sync.DISCOVERY_ERROR,
                                ),
                            syncStatus =
                                favoriteSyncStatus(
                                    info?.state,
                                    info?.outputData?.getInt(AccountDiscoveryWorker.FAVORITE_REMAINING, -1) ?: -1,
                                ),
                        )
                    }.collectLatest { mutableState.value = it }
            }
    }

    fun refresh() {
        accountId?.let(transfers::refreshAccount)
    }

    fun remove(resource: ResourceEntity) {
        viewModelScope.launch {
            runCatching { withContext(Dispatchers.IO) { transfers.setFavorite(resource, false) } }
                .onFailure {
                    mutableState.value =
                        mutableState.value.copy(error = it.toOpenCloudError().safeMessage(getApplication()))
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
