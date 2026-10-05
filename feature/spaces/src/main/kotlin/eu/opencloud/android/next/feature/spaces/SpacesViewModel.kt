package eu.opencloud.android.next.feature.spaces

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.safeMessage
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.sync.EncryptedLocationManagementRepository
import eu.opencloud.android.next.core.sync.SpaceManagementManager
import eu.opencloud.android.next.core.sync.SupersededDiscovery
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import eu.opencloud.android.next.core.sync.VaultOfflineStore
import eu.opencloud.android.next.core.sync.VaultRepository
import eu.opencloud.android.next.core.sync.VaultRootCatalog
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.URI

class SpacesViewModel(
    application: Application,
) : AndroidViewModel(application) {
    private val store = FileBrowserStore(FileBrowserDatabase.create(application))
    private val manager = SpaceManagementManager(application, store)
    private val vaults = VaultRepository(application, store)
    private val encryptedManagement = EncryptedLocationManagementRepository(application)
    private val offlineVaults = VaultOfflineStore(application)
    private val rootCatalog = VaultRootCatalog(application)
    private val mutableState = MutableStateFlow(SpacesUiState())
    val state = mutableState.asStateFlow()
    private var accountId: String? = null
    private var observation: Job? = null
    private var refreshJob: Job? = null
    private var encryptedRefreshJob: Job? = null

    @Suppress("TooGenericExceptionCaught") // UI boundary uses safe typed errors and preserves cancellation.
    fun refresh(clearError: Boolean = true) {
        val account = accountId ?: return
        refreshEncrypted(account)
        if (state.value.busy || refreshJob?.isActive == true) return
        mutableState.value = state.value.copy(loading = true, error = if (clearError) null else state.value.error)
        refreshJob =
            viewModelScope.launch {
                try {
                    val spaces =
                        withContext(Dispatchers.IO) {
                            try {
                                manager.refreshMembership(account)
                            } catch (_: SupersededDiscovery) {
                                // A newer local discovery owns the snapshot; still load the authoritative
                                // management listing and current member-space cache below.
                            }
                            manager.listSpaces(account)
                        }
                    val memberSpaces = withContext(Dispatchers.IO) { store.spaces(account) }
                    if (accountId != account) return@launch
                    mutableState.value =
                        state.value.copy(
                            spaces = spaces,
                            loading = false,
                            browsableIds =
                                memberSpaces
                                    .filterNot { it.isDisabled || it.isDeleted }
                                    .map { it.driveId }
                                    .toSet(),
                        )
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (error: Exception) {
                    if (accountId == account) {
                        reportError(error.toOpenCloudError().safeMessage(getApplication()))
                    }
                }
            }
    }

    @Suppress("TooGenericExceptionCaught") // A failed vault lookup must not hide ordinary Spaces.
    private fun refreshEncrypted(account: String) {
        // A creation-triggered refresh must supersede a lookup started before the new Space existed.
        encryptedRefreshJob?.cancel()
        mutableState.value = state.value.copy(encryptedLoading = true, encryptedError = false)
        encryptedRefreshJob =
            viewModelScope.launch {
                try {
                    val discovery =
                        discoverEncryptedSpaceRoots(
                            account,
                            loadOffline = { withContext(Dispatchers.IO) { offlineVaults.locations(account) } },
                            loadRemembered = { withContext(Dispatchers.IO) { rootCatalog.spaceRoots(account) } },
                            loadAvailable = { withContext(Dispatchers.IO) { vaults.encryptedSpaces(account) } },
                            loadDisabled = {
                                withContext(
                                    Dispatchers.IO,
                                ) { encryptedManagement.disabledSpaces(account) }
                            },
                            onCached = { cached ->
                                if (accountId == account) {
                                    mutableState.value =
                                        state.value.copy(
                                            encryptedSpaces = cached,
                                            encryptedLoading = false,
                                            encryptedError = false,
                                        )
                                }
                            },
                            rememberOnline = { roots ->
                                withContext(Dispatchers.IO) { rootCatalog.replaceSpaceRoots(account, roots) }
                            },
                            removeOffline = { location ->
                                withContext(Dispatchers.IO) {
                                    offlineVaults.remove(
                                        VaultIdentity(
                                            location.accountId,
                                            location.canonicalServer,
                                            location.driveId,
                                            location.remoteVaultId,
                                        ),
                                    )
                                }
                            },
                        )
                    if (accountId == account) {
                        mutableState.value =
                            state.value.copy(
                                encryptedSpaces = discovery.locations,
                                encryptedLoading = false,
                                encryptedError = discovery.hadFailure,
                            )
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (accountId == account) {
                        mutableState.value =
                            state.value.copy(
                                encryptedSpaces = emptyList(),
                                encryptedLoading = false,
                                encryptedError = true,
                            )
                    }
                }
            }
    }

    fun load(accountId: String) {
        if (this.accountId == accountId) {
            refresh()
            return
        }
        this.accountId = accountId
        observation?.cancel()
        refreshJob?.cancel()
        encryptedRefreshJob?.cancel()
        mutableState.value = SpacesUiState()
        observation =
            viewModelScope.launch {
                val cached = withContext(Dispatchers.IO) { store.spaces(accountId) }
                if (this@SpacesViewModel.accountId == accountId) {
                    mutableState.value =
                        state.value.copy(spaces = cached.filter { it.type.equals("project", true) && !it.isDeleted })
                    refresh()
                }
            }
    }

    @Suppress("TooGenericExceptionCaught") // UI boundary uses safe typed errors and preserves cancellation.
    fun perform(
        space: SpaceEntity,
        action: SpaceAction,
        value: String,
    ) {
        val account = accountId ?: return
        if (state.value.busy || state.value.loading || space.accountId != account) return
        mutableState.value = state.value.copy(busy = true, error = null)
        viewModelScope.launch {
            try {
                withContext(Dispatchers.IO) {
                    when (action) {
                        SpaceAction.RENAME -> manager.update(account, space.driveId, name = value.trim())
                        SpaceAction.SUBTITLE -> manager.update(account, space.driveId, subtitle = value.trim())
                        SpaceAction.QUOTA ->
                            manager.update(
                                account,
                                space.driveId,
                                quotaBytes = requireNotNull(quotaBytes(value)),
                            )
                        SpaceAction.DISABLE -> manager.disable(account, space.driveId)
                        SpaceAction.ENABLE -> manager.enable(account, space.driveId)
                        SpaceAction.DELETE -> {
                            require(value == space.name)
                            manager.permanentlyDelete(account, space.driveId)
                        }
                        else -> Unit
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                reportError(error.toOpenCloudError().safeMessage(getApplication()))
            } finally {
                mutableState.value = state.value.copy(busy = false)
                refresh(clearError = false)
            }
        }
    }

    suspend fun webUrl(space: SpaceEntity): String {
        val account = accountId
        if (account == null || space.accountId != account || !AppLock(getApplication()).canOpenApp()) {
            throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        }
        val server = withContext(Dispatchers.IO) { requireNotNull(store.account(account)).serverUrl }
        return trustedSpaceWebUrl(server, space.webUrl) ?: throw OpenCloudException(OpenCloudError.Trust)
    }

    fun reportError(message: String) {
        mutableState.value = state.value.copy(loading = false, error = message)
    }

    fun dismissError() {
        mutableState.value = state.value.copy(error = null)
    }
}

internal data class EncryptedSpaceDiscoveryResult(
    val locations: List<VaultLocation>,
    val hadFailure: Boolean,
)

@Suppress(
    "TooGenericExceptionCaught",
    "LongParameterList",
    "CyclomaticComplexMethod",
    "ThrowsCount",
) // Discovery combines cached/live/disabled sources with distinct trust and cancellation behavior.
internal suspend fun discoverEncryptedSpaceRoots(
    accountId: String,
    loadOffline: suspend () -> List<VaultLocation>,
    loadRemembered: suspend () -> List<VaultLocation> = { emptyList() },
    loadAvailable: suspend () -> List<VaultLocation>,
    loadDisabled: suspend () -> List<VaultLocation>,
    onCached: (List<VaultLocation>) -> Unit = {},
    rememberOnline: suspend (List<VaultLocation>) -> Unit = {},
    removeOffline: suspend (VaultLocation) -> Unit,
): EncryptedSpaceDiscoveryResult {
    fun scoped(locations: List<VaultLocation>) =
        locations.filter {
            it.accountId == accountId &&
                it.kind == VaultLocationKind.SPACE_VAULT &&
                it.isVaultRoot
        }

    val saved =
        try {
            scoped(loadOffline()).map { it.copy(offlineOnly = true) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            emptyList()
        }
    val remembered =
        try {
            scoped(loadRemembered()).map { it.copy(offlineOnly = true) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            emptyList()
        }
    val cached = offlineSpaceAvailability(mergeOfflineSpaceDescriptors(remembered, saved), saved)
    if (cached.isNotEmpty()) onCached(cached)
    val available =
        try {
            scoped(loadAvailable())
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            val networkUnavailable =
                when (val error = failure.toOpenCloudError()) {
                    OpenCloudError.Connectivity, OpenCloudError.Timeout -> true
                    is OpenCloudError.ServerFailure -> error.statusCode in 500..599
                    else -> false
                }
            if (networkUnavailable && cached.isNotEmpty()) {
                return EncryptedSpaceDiscoveryResult(cached, hadFailure = false)
            }
            throw failure
        }
    val disabled =
        try {
            scoped(loadDisabled()).map { it.copy(isDisabled = true) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // Current encrypted-space discovery remains usable if only the disabled-space lookup fails.
            emptyList()
        }
    val disabledKeys = disabled.mapTo(mutableSetOf(), ::vaultLocationKey)
    cached.filter { vaultLocationKey(it) in disabledKeys }.forEach { location ->
        try {
            removeOffline(location)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            // The disabled response is authoritative; failed cleanup does not make this snapshot visible.
        }
    }
    val disabledDrives = disabled.mapTo(mutableSetOf()) { it.driveId }
    val locations =
        (disabled + available.filterNot { it.driveId in disabledDrives })
            .distinctBy(::vaultLocationKey)
    try {
        rememberOnline(available.filterNot { it.driveId in disabledDrives })
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        // Live results remain usable if offline descriptor persistence fails.
    }
    return EncryptedSpaceDiscoveryResult(locations, hadFailure = false)
}

internal fun mergeOfflineSpaceDescriptors(
    preferred: List<VaultLocation>,
    other: List<VaultLocation>,
): List<VaultLocation> = (preferred + other).distinctBy(::vaultLocationKey)

internal fun offlineSpaceAvailability(
    remembered: List<VaultLocation>,
    saved: List<VaultLocation>,
): List<VaultLocation> {
    val savedKeys = saved.mapTo(mutableSetOf(), ::vaultLocationFullKey)
    return remembered.map { location ->
        location.copy(offlineOnly = true, offlineUnavailable = vaultLocationFullKey(location) !in savedKeys)
    }
}

private fun vaultLocationKey(location: VaultLocation) =
    listOf(location.accountId, location.canonicalServer, location.driveId, location.remoteVaultId)

private fun vaultLocationFullKey(location: VaultLocation) =
    listOf(
        location.accountId,
        location.canonicalServer,
        location.driveId,
        location.remoteVaultId,
        location.rootWebDavUrl,
        location.vaultPath.trim('/'),
    )

internal fun trustedSpaceWebUrl(
    server: String,
    webUrl: String?,
): String? =
    try {
        val base = URI(server)
        val target = URI(webUrl ?: "")

        fun URI.portOrDefault() = if (port == -1) 443 else port
        webUrl?.takeIf {
            base.scheme == "https" &&
                target.scheme == "https" &&
                target.host != null &&
                target.host.equals(base.host, ignoreCase = true) &&
                target.portOrDefault() == base.portOrDefault() &&
                target.userInfo == null &&
                target.fragment == null
        }
    } catch (_: java.net.URISyntaxException) {
        null
    }
