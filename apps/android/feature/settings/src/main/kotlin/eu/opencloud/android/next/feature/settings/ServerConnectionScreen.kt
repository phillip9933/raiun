package eu.opencloud.android.next.feature.settings

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import eu.opencloud.android.next.core.security.ClientCertificatePolicy
import eu.opencloud.android.next.core.security.ServerConnectionRoute
import eu.opencloud.android.next.core.security.TlsPolicy
import eu.opencloud.android.next.core.security.WifiRouteMode
import eu.opencloud.android.next.core.security.WifiRouteStatus
import eu.opencloud.android.next.core.security.WifiServerRoute
import eu.opencloud.android.next.core.security.WifiServerRoutePolicy
import eu.opencloud.android.next.core.security.WifiServerRouteStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

@Composable
@Suppress("LongMethod", "CyclomaticComplexMethod")
fun ServerConnectionScreen(
    serverUrl: String,
    onNavigateBack: () -> Unit,
) {
    BackHandler(onBack = onNavigateBack)
    val context = LocalContext.current
    val canonicalServerUrl =
        remember(serverUrl) {
            val input = if ("://" in serverUrl) serverUrl else "https://$serverUrl"
            runCatching { ClientCertificatePolicy.normalizeServerUrl(input) }.getOrNull()
        }
    val scope = rememberCoroutineScope()
    val snackbar = remember(canonicalServerUrl) { SnackbarHostState() }
    val routeStore = remember(context) { WifiServerRouteStore(context) }
    val connectionRoute = remember(context) { ServerConnectionRoute(context) }
    val certificatePolicy = remember(context) { ClientCertificatePolicy(context) }
    var enabled by remember(canonicalServerUrl) { mutableStateOf(false) }
    var localAddress by remember(canonicalServerUrl) { mutableStateOf("") }
    var ssid by remember(canonicalServerUrl) { mutableStateOf("") }
    var mode by remember(canonicalServerUrl) { mutableStateOf(ConnectionMode.AUTOMATIC) }
    var origins by remember(canonicalServerUrl) { mutableStateOf("") }
    var selectedAlias by remember(canonicalServerUrl) { mutableStateOf<String?>(null) }
    var hasSavedCertificate by remember(canonicalServerUrl) { mutableStateOf(false) }
    var removeCertificate by remember(canonicalServerUrl) { mutableStateOf(false) }
    var status by remember(canonicalServerUrl) { mutableStateOf<WifiRouteStatus?>(null) }
    var busy by remember(canonicalServerUrl) { mutableStateOf(false) }
    var testing by remember(canonicalServerUrl) { mutableStateOf(false) }
    var testResult by remember(canonicalServerUrl) { mutableStateOf<Boolean?>(null) }
    var loading by remember(canonicalServerUrl) { mutableStateOf(true) }
    var loadFailed by remember(canonicalServerUrl) { mutableStateOf(false) }
    var savedAlias by remember(canonicalServerUrl) { mutableStateOf<String?>(null) }
    var savedOrigins by remember(canonicalServerUrl) { mutableStateOf<Set<String>>(emptySet()) }

    fun refreshConnection(updateSsid: Boolean) {
        canonicalServerUrl?.let { canonical ->
            scope.refreshConnection(connectionRoute, canonical, updateSsid, { value, currentStatus ->
                if (updateSsid) value?.let { ssid = it }
                status = currentStatus
                loadFailed = false
            }, {
                status = null
                loadFailed = true
            })
        }
    }

    val permissionLauncher =
        rememberLauncherForActivityResult(
            ActivityResultContracts.RequestMultiplePermissions(),
        ) { refreshConnection(updateSsid = true) }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        refreshConnection(updateSsid = false)
    }

    LaunchedEffect(canonicalServerUrl) {
        loading = true
        val canonical = canonicalServerUrl
        if (canonical == null) {
            loadFailed = true
            loading = false
            return@LaunchedEffect
        }
        try {
            val loaded = withContext(Dispatchers.IO) { routeStore.find(canonical) }
            if (loaded != null) {
                enabled = loaded.enabled
                localAddress = loaded.localServerUrl
                ssid = loaded.ssid
                mode = loaded.mode.toConnectionMode()
            }
            val binding = withContext(Dispatchers.IO) { certificatePolicy.load(canonical) }
            hasSavedCertificate = binding != null
            savedAlias = binding?.alias
            savedOrigins = binding?.origins.orEmpty()
            origins = savedOrigins.sorted().joinToString("\n")
            status = withContext(Dispatchers.IO) { readRouteStatus(connectionRoute, canonical) }
            loadFailed = false
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            loadFailed = true
        } finally {
            loading = false
        }
    }

    val viewState =
        ConnectionViewState(
            serverUrl = canonicalServerUrl ?: serverUrl,
            enabled = enabled,
            localAddress = localAddress,
            ssid = ssid,
            mode = mode,
            status = status,
            testing = testing,
            testResult = testResult,
            busy = busy,
            loading = loading,
            loadFailed = loadFailed,
            origins = origins,
            certificateSelected = selectedAlias != null || (hasSavedCertificate && !removeCertificate),
            canRemoveCertificate = hasSavedCertificate,
            removingCertificate = removeCertificate,
        )
    val actions =
        ConnectionViewActions(
            onEnabledChange = { enabled = it },
            onLocalAddressChange = { localAddress = it },
            onSsidChange = { ssid = it },
            onModeChange = { mode = it },
            onCurrentWifi = {
                permissionLauncher.launch(
                    arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION),
                )
            },
            onTest = {
                testing = true
                testResult = null
                scope.launch {
                    try {
                        testResult =
                            withContext(Dispatchers.IO) {
                                testCanonicalConnection(context, requireNotNull(canonicalServerUrl))
                            }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (_: Exception) {
                        testResult = false
                    } finally {
                        testing = false
                    }
                }
            },
            onOriginsChange = { origins = it },
            onChooseCertificate = {
                if (!openCertificateChooser(
                        context,
                        certificatePolicy,
                        origins,
                        canonicalServerUrl,
                    ) { selectedAlias = it }
                ) {
                    scope.launch { snackbar.showSnackbar(context.getString(R.string.connection_invalid)) }
                }
            },
            onRemoveCertificate = {
                removeCertificate = true
                selectedAlias = null
            },
            onCancelRemoval = { removeCertificate = false },
            onCancel = onNavigateBack,
            onSave = {
                busy = true
                scope.launch {
                    val saved =
                        persistConnection(
                            routeStore,
                            certificatePolicy,
                            ConnectionDraft(
                                serverUrl = requireNotNull(canonicalServerUrl),
                                ssid = ssid,
                                localAddress = localAddress,
                                enabled = enabled,
                                mode = mode,
                                origins = origins,
                                removeCertificate = removeCertificate,
                                selectedAlias = selectedAlias,
                                hasSavedCertificate = hasSavedCertificate,
                                savedAlias = savedAlias,
                                savedOrigins = savedOrigins,
                            ),
                        )
                    busy = false
                    if (saved) {
                        onNavigateBack()
                    } else {
                        snackbar.showSnackbar(
                            context.getString(R.string.connection_invalid),
                        )
                    }
                }
            },
        )
    ConnectionScreenContent(viewState, actions, onNavigateBack, snackbar)
}

private fun readRouteStatus(
    route: ServerConnectionRoute,
    serverUrl: String,
): WifiRouteStatus = route.activeStatus(serverUrl)

private fun CoroutineScope.refreshConnection(
    route: ServerConnectionRoute,
    serverUrl: String,
    updateSsid: Boolean,
    onStatus: (String?, WifiRouteStatus) -> Unit,
    onFailure: () -> Unit,
) {
    launch {
        try {
            val current =
                withContext(Dispatchers.IO) {
                    route.activeSsid() to readRouteStatus(route, serverUrl)
                }
            onStatus(current.first.takeIf { updateSsid }, current.second)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            onFailure()
        }
    }
}

private fun openCertificateChooser(
    context: Context,
    policy: ClientCertificatePolicy,
    origins: String,
    canonicalServerUrl: String?,
    onAliasSelected: (String?) -> Unit,
): Boolean {
    val activity = context.findActivity()
    return if (activity != null && canonicalServerUrl != null) {
        runCatching {
            val chooserOrigin =
                parseOrigins(origins).firstOrNull()?.let(ClientCertificatePolicy::normalizeOrigin)
                    ?: throw IllegalArgumentException("An HTTPS certificate origin is required.")
            policy.chooseAlias(activity, chooserOrigin, onAliasSelected)
        }.isSuccess
    } else {
        false
    }
}

private data class ConnectionDraft(
    val serverUrl: String,
    val ssid: String,
    val localAddress: String,
    val enabled: Boolean,
    val mode: ConnectionMode,
    val origins: String,
    val removeCertificate: Boolean,
    val selectedAlias: String?,
    val hasSavedCertificate: Boolean,
    val savedAlias: String?,
    val savedOrigins: Set<String>,
)

private suspend fun persistConnection(
    routeStore: WifiServerRouteStore,
    certificatePolicy: ClientCertificatePolicy,
    draft: ConnectionDraft,
): Boolean =
    try {
        withContext(Dispatchers.IO) {
            val route =
                WifiServerRoute(
                    canonicalServerUrl = draft.serverUrl,
                    ssid = draft.ssid,
                    localServerUrl = draft.localAddress.trim(),
                    enabled = draft.enabled,
                    mode = draft.mode.toWifiRouteMode(),
                )
            val routeCanBeRemoved = !draft.enabled && (draft.ssid.isBlank() || draft.localAddress.isBlank())
            if (!routeCanBeRemoved) WifiServerRoutePolicy.validate(route)
            val origins =
                if (draft.needsCertificateOrigins()) {
                    parseOrigins(draft.origins).map { ClientCertificatePolicy.normalizeOrigin(it) }.toSet()
                } else {
                    emptySet()
                }
            val saveCertificate =
                draft.selectedAlias != null ||
                    (draft.hasSavedCertificate && !draft.removeCertificate && origins != draft.savedOrigins)
            when {
                draft.removeCertificate -> certificatePolicy.clear(draft.serverUrl)
                saveCertificate ->
                    certificatePolicy.save(
                        draft.serverUrl,
                        origins,
                        requireNotNull(draft.selectedAlias ?: draft.savedAlias),
                    )
            }
            if (routeCanBeRemoved) routeStore.remove(draft.serverUrl) else routeStore.put(route)
        }
        true
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        false
    }

private fun testCanonicalConnection(
    context: Context,
    serverUrl: String,
): Boolean =
    try {
        val server = requireNotNull(serverUrl.toHttpUrlOrNull()) { "Invalid HTTPS server address." }
        val endpoint = server.newBuilder().addPathSegment("status.php").build()
        check(endpoint.isHttps && endpoint.host == server.host) { "Connection test must use the canonical HTTPS host." }
        val client =
            TlsPolicy(context).applyTo(
                OkHttpClient.Builder().callTimeout(15, TimeUnit.SECONDS).build(),
                serverUrl,
            )
        val testClient =
            client
                .newBuilder()
                .followRedirects(false)
                .followSslRedirects(false)
                .build()
        testClient
            .newCall(
                Request
                    .Builder()
                    .url(endpoint)
                    .get()
                    .build(),
            ).execute()
            .use { it.isSuccessful }
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        false
    }

private fun parseOrigins(value: String): List<String> = value.lines().map(String::trim).filter(String::isNotEmpty)

private fun ConnectionMode.toWifiRouteMode(): WifiRouteMode =
    when (this) {
        ConnectionMode.PUBLIC -> WifiRouteMode.PUBLIC
        ConnectionMode.AUTOMATIC -> WifiRouteMode.AUTOMATIC
    }

private fun WifiRouteMode.toConnectionMode(): ConnectionMode =
    when (this) {
        WifiRouteMode.PUBLIC -> ConnectionMode.PUBLIC
        WifiRouteMode.AUTOMATIC -> ConnectionMode.AUTOMATIC
        WifiRouteMode.LOCAL -> ConnectionMode.AUTOMATIC
    }

private tailrec fun Context.findActivity(): Activity? =
    when (this) {
        is Activity -> this
        is ContextWrapper -> baseContext.findActivity()
        else -> null
    }

private fun ConnectionDraft.needsCertificateOrigins(): Boolean =
    selectedAlias != null || (hasSavedCertificate && !removeCertificate)
