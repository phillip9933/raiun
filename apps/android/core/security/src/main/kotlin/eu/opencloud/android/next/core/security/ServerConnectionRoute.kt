package eu.opencloud.android.next.core.security

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiInfo
import android.net.wifi.WifiManager
import android.os.Build
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.TransportPolicyException
import okhttp3.ConnectionPool
import okhttp3.Dns
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import java.net.InetAddress
import java.net.Proxy
import java.util.concurrent.ConcurrentHashMap

/** Captures the route for one HTTP client. Callers create a new snapshot for each independent operation. */
data class ServerConnectionSnapshot(
    val route: ValidatedWifiServerRoute?,
    val status: WifiRouteStatus,
    val network: Network?,
) {
    val isLocal: Boolean get() = status == WifiRouteStatus.ACTIVE && route != null && network != null
}

/** Observes the default network. Android 12+ supplies unredacted WifiInfo only through a flagged callback. */
class WifiServerNetworkMonitor private constructor(
    context: Context,
) {
    private val app = context.applicationContext
    private val connectivity = app.getSystemService(ConnectivityManager::class.java)
    private val wifi = app.getSystemService(WifiManager::class.java)
    private val location = app.getSystemService(LocationManager::class.java)
    private val callbackSsids = ConcurrentHashMap<Network, String>()
    private var registered = false
    private var lastEligible: Boolean? = null
    private val callback: ConnectivityManager.NetworkCallback =
        if (Build.VERSION.SDK_INT >= 31) {
            object : ConnectivityManager.NetworkCallback(
                ConnectivityManager.NetworkCallback.FLAG_INCLUDE_LOCATION_INFO,
            ) {
                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) = recordCapabilities(network, capabilities)

                override fun onLost(network: Network) = forget(network)
            }
        } else {
            object : ConnectivityManager.NetworkCallback() {
                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) = recordCapabilities(network, capabilities)

                override fun onLost(network: Network) = forget(network)
            }
        }

    private fun recordCapabilities(
        network: Network,
        capabilities: NetworkCapabilities,
    ) {
        val ssid =
            if (Build.VERSION.SDK_INT >= 29) {
                (capabilities.transportInfo as? WifiInfo)?.ssid?.let(::usableSsid)
            } else {
                null
            }
        if (ssid == null) callbackSsids.remove(network) else callbackSsids[network] = ssid
    }

    private fun forget(network: Network) {
        callbackSsids.remove(network)
    }

    fun current(): Pair<Network?, WifiRouteObservation> =
        runCatching { readCurrent() }.getOrElse {
            null to WifiRouteObservation(false, false, false, null)
        }

    private fun readCurrent(): Pair<Network?, WifiRouteObservation> {
        val permission =
            app.checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val locationEnabled =
            if (Build.VERSION.SDK_INT >= 28) {
                location.isLocationEnabled
            } else {
                location.isProviderEnabled(LocationManager.GPS_PROVIDER) ||
                    location.isProviderEnabled(LocationManager.NETWORK_PROVIDER)
            }
        val available = permission && locationEnabled
        ensureRegistration(available)
        val network = connectivity.activeNetwork
        val capabilities = network?.let(connectivity::getNetworkCapabilities)
        val isWifi = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
        val isVpn = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
        val ssid =
            if (!available || !isWifi || isVpn) {
                null
            } else if (Build.VERSION.SDK_INT >= 31) {
                network?.let(callbackSsids::get)
                    ?: (capabilities?.transportInfo as? WifiInfo)?.ssid?.let(::usableSsid)
                    ?: legacySsid()
            } else {
                (if (Build.VERSION.SDK_INT >= 29) capabilities?.transportInfo as? WifiInfo else null)
                    ?.ssid
                    ?.let(::usableSsid)
                    ?: legacySsid()
            }
        return network to WifiRouteObservation(available, isWifi, isVpn, ssid)
    }

    @Suppress("DEPRECATION")
    private fun legacySsid(): String? = wifi.connectionInfo?.ssid?.let(::usableSsid)

    private fun ensureRegistration(eligible: Boolean) =
        synchronized(this) {
            if (registered && lastEligible == eligible) return@synchronized
            if (registered) runCatching { connectivity.unregisterNetworkCallback(callback) }
            callbackSsids.clear()
            lastEligible = eligible
            registered = eligible && runCatching { connectivity.registerDefaultNetworkCallback(callback) }.isSuccess
        }

    companion object {
        @Volatile private var processInstance: WifiServerNetworkMonitor? = null

        fun shared(context: Context): WifiServerNetworkMonitor =
            processInstance ?: synchronized(this) {
                processInstance ?: WifiServerNetworkMonitor(context.applicationContext).also { processInstance = it }
            }
    }
}

private fun usableSsid(value: String): String? =
    value
        .takeUnless { it.isBlank() || it == WifiManager.UNKNOWN_SSID }
        ?.removeSurrounding("\"")
        ?.takeIf(String::isNotBlank)

/** Keeps every URL canonical; only the configured canonical host resolves to the local address. */
class ServerConnectionRoute(
    context: Context,
    private val store: WifiServerRouteStore = WifiServerRouteStore(context),
) {
    private val app = context.applicationContext
    private val monitor by lazy { WifiServerNetworkMonitor.shared(app) }

    fun activeStatus(canonicalServerUrl: String): WifiRouteStatus = createSnapshot(canonicalServerUrl).status

    fun activeSsid(): String? = monitor.current().second.ssid

    @Suppress("TooGenericExceptionCaught") // Corrupt persisted route state must fail closed with a safe typed error.
    fun createSnapshot(canonicalServerUrl: String): ServerConnectionSnapshot {
        val route =
            try {
                store.find(canonicalServerUrl)?.let(WifiServerRoutePolicy::validate)
            } catch (_: Exception) {
                throw TransportPolicyException(OpenCloudError.NetworkRouteChanged)
            }
        if (route == null || !route.enabled || route.mode == WifiRouteMode.PUBLIC) {
            return ServerConnectionSnapshot(route, WifiRouteStatus.DISABLED, null)
        }
        val (network, observation) = monitor.current()
        val status = WifiServerRoutePolicy.status(route, observation)
        return ServerConnectionSnapshot(route, status, network.takeIf { status == WifiRouteStatus.ACTIVE })
    }

    /** A changed network fails every call before sending it. Only the canonical host gets local DNS. */
    fun applyTo(
        base: OkHttpClient,
        snapshot: ServerConnectionSnapshot,
    ): OkHttpClient {
        val route = snapshot.route ?: return base
        val pool = ConnectionPool()
        val builder =
            base
                .newBuilder()
                .connectionPool(pool)
                .addInterceptor { chain ->
                    val current = createSnapshot(route.canonicalServerUrl)
                    if (!snapshot.sameRoute(current)) {
                        pool.evictAll()
                        throw TransportPolicyException(OpenCloudError.NetworkRouteChanged)
                    }
                    // OkHttp Dns sees only the hostname. Refuse a different port/scheme on that host
                    // before DNS can route it to the configured local address.
                    val requestUrl = chain.request().url
                    if (snapshot.isLocal) requireCompatibleCanonicalOrigin(route, requestUrl)
                    chain.proceed(chain.request())
                }
        if (snapshot.isLocal) {
            val network = requireNotNull(snapshot.network)
            builder
                .proxy(Proxy.NO_PROXY)
                .dns(
                    object : Dns {
                        override fun lookup(hostname: String): List<InetAddress> =
                            network.getAllByName(dnsHostFor(route, hostname)).toList()
                    },
                ).socketFactory(network.socketFactory)
        }
        return builder.build()
    }

    /** Shared process monitor remains registered so background workers see later network changes. */
    fun close() = Unit
}

internal fun ServerConnectionSnapshot.sameRoute(current: ServerConnectionSnapshot): Boolean =
    routeState() == current.routeState()

internal data class RouteState(
    val route: ValidatedWifiServerRoute?,
    val status: WifiRouteStatus,
    val networkIdentity: Any?,
)

internal fun ServerConnectionSnapshot.routeState() = RouteState(route, status, network)

internal fun dnsHostFor(
    route: ValidatedWifiServerRoute,
    requestedHost: String,
): String = if (requestedHost == route.canonical.host) route.local.host else requestedHost

internal fun isIncompatibleCanonicalOrigin(
    route: ValidatedWifiServerRoute,
    url: HttpUrl,
): Boolean = url.host == route.canonical.host && (!url.isHttps || url.port != route.canonical.port)

internal fun requireCompatibleCanonicalOrigin(
    route: ValidatedWifiServerRoute,
    url: HttpUrl,
) {
    if (isIncompatibleCanonicalOrigin(route, url)) throw TransportPolicyException(OpenCloudError.Trust)
}
