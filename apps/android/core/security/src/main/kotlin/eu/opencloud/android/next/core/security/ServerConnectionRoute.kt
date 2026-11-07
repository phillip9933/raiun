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
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import java.net.InetAddress
import java.net.Proxy
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.net.SocketFactory

/** Captures the route for one HTTP client. Callers create a new snapshot for each independent operation. */
data class ServerConnectionSnapshot(
    val route: ValidatedWifiServerRoute?,
    val status: WifiRouteStatus,
    val network: Network?,
    internal val canonicalServerUrl: String? = route?.canonicalServerUrl,
    internal val networkRevision: Long? = null,
) {
    internal var transportGuard: TransportGuard? = null

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
    private val callbackObservations = ConcurrentHashMap<Network, WifiRouteObservation>()
    private val observationRevision = AtomicLong()
    private val observationLock = Any()

    @Volatile private var callbackNetwork: Network? = null
    private var registered = false
    private var lastEligible: Boolean? = null
    private val callback: ConnectivityManager.NetworkCallback =
        if (Build.VERSION.SDK_INT >= 31) {
            object : ConnectivityManager.NetworkCallback(
                ConnectivityManager.NetworkCallback.FLAG_INCLUDE_LOCATION_INFO,
            ) {
                override fun onAvailable(network: Network) = recordAvailable(network)

                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) = recordCapabilities(network, capabilities)

                override fun onLost(network: Network) = forget(network)
            }
        } else {
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = recordAvailable(network)

                override fun onCapabilitiesChanged(
                    network: Network,
                    capabilities: NetworkCapabilities,
                ) = recordCapabilities(network, capabilities)

                override fun onLost(network: Network) = forget(network)
            }
        }

    private fun recordAvailable(network: Network) {
        val previous =
            synchronized(observationLock) {
                val previous = callbackNetwork
                callbackNetwork = network
                if (previous != null && previous != network) observationRevision.incrementAndGet()
                previous
            }
        if (previous != null && previous != network) ScopedTransportCache.revokeRouteNetwork(previous)
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
        val observation =
            WifiRouteObservation(
                true,
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                ssid,
            )
        val changed =
            synchronized(observationLock) {
                val prior = callbackObservations.put(network, observation)
                (prior != null && prior != observation).also { if (it) observationRevision.incrementAndGet() }
            }
        if (changed) ScopedTransportCache.revokeRouteNetwork(network)
    }

    private fun forget(network: Network) {
        synchronized(observationLock) {
            observationRevision.incrementAndGet()
            if (callbackNetwork == network) callbackNetwork = null
            callbackObservations.remove(network)
        }
        ScopedTransportCache.revokeRouteNetwork(network)
    }

    fun current(): Pair<Network?, WifiRouteObservation> =
        runCatching { readCurrent() }.getOrElse {
            null to WifiRouteObservation(false, false, false, null)
        }

    internal fun capture(): Pair<Pair<Network?, WifiRouteObservation>, Long> {
        val before = observationRevision.get()
        val observation = current()
        val after = observationRevision.get()
        // A concurrent callback makes this capture ineligible; admission must use a fresh snapshot.
        val stable = if (before == after) observation else null to WifiRouteObservation(false, false, false, null)
        return stable to after
    }

    internal fun admit(
        revision: Long,
        scope: Any,
        state: RouteState,
    ): TransportAdmission? =
        synchronized(observationLock) {
            if (observationRevision.get() == revision) ScopedTransportCache.guardDeferred(scope, state) else null
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
                network?.let(callbackObservations::get)?.ssid
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

    private fun ensureRegistration(eligible: Boolean) {
        val retiredNetworks =
            synchronized(this) {
                if (registered && lastEligible == eligible) return
                if (registered) runCatching { connectivity.unregisterNetworkCallback(callback) }
                val previous =
                    synchronized(observationLock) {
                        val previous = (callbackObservations.keys + listOfNotNull(callbackNetwork)).distinct()
                        if (previous.isNotEmpty() || (lastEligible != null && lastEligible != eligible)) {
                            observationRevision.incrementAndGet()
                        }
                        callbackObservations.clear()
                        callbackNetwork = null
                        previous
                    }
                lastEligible = eligible
                registered = eligible && runCatching { connectivity.registerDefaultNetworkCallback(callback) }.isSuccess
                previous
            }
        retiredNetworks.forEach(ScopedTransportCache::revokeRouteNetwork)
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
        val captured =
            try {
                val previous = store.find(canonicalServerUrl)
                val observed =
                    if (previous?.enabled == true &&
                        previous.mode != WifiRouteMode.PUBLIC
                    ) {
                        monitor.capture()
                    } else {
                        null
                    }
                store.withRoute(canonicalServerUrl) { persisted ->
                    val route = persisted?.let(WifiServerRoutePolicy::validate)
                    val snapshot =
                        if (route == null || !route.enabled || route.mode == WifiRouteMode.PUBLIC) {
                            ServerConnectionSnapshot(route, WifiRouteStatus.DISABLED, null, canonicalServerUrl)
                        } else {
                            val (capturedNetwork, revision) =
                                observed
                                    ?: ((null to WifiRouteObservation(false, false, false, null)) to 0L)
                            val (network, observation) = capturedNetwork
                            val status = WifiServerRoutePolicy.status(route, observation)
                            ServerConnectionSnapshot(
                                route,
                                status,
                                network.takeIf {
                                    status == WifiRouteStatus.ACTIVE
                                },
                                canonicalServerUrl,
                                revision,
                            )
                        }
                    val scope = store.transportScope(canonicalServerUrl)
                    val admission =
                        if (snapshot.networkRevision == null) {
                            ScopedTransportCache.guardDeferred(scope, snapshot.routeState())
                        } else {
                            monitor.admit(snapshot.networkRevision, scope, snapshot.routeState())
                                ?: throw TransportPolicyException(OpenCloudError.NetworkRouteChanged)
                        }
                    snapshot to admission
                }
            } catch (_: Exception) {
                ScopedTransportCache.revoke(store.transportScope(canonicalServerUrl))
                throw TransportPolicyException(OpenCloudError.NetworkRouteChanged)
            }
        captured.second.retire()
        return captured.first.also { it.transportGuard = captured.second.guard }
    }

    /** A changed network fails every call before sending it. Only the canonical host gets local DNS. */
    fun applyTo(
        base: OkHttpClient,
        snapshot: ServerConnectionSnapshot,
    ): OkHttpClient {
        val server = snapshot.canonicalServerUrl ?: return base
        val route = snapshot.route
        val guard =
            snapshot.transportGuard ?: ScopedTransportCache.guard(store.transportScope(server), snapshot.routeState())
        val validation =
            Interceptor { chain ->
                val current = createSnapshot(server)
                if (!guard.isCurrent() || !snapshot.sameRoute(current)) {
                    ScopedTransportCache.revoke(store.transportScope(server))
                    throw TransportPolicyException(OpenCloudError.NetworkRouteChanged)
                }
                // DNS sees only the hostname; reject a different canonical scheme/port before local routing.
                if (snapshot.isLocal) requireCompatibleCanonicalOrigin(requireNotNull(route), chain.request().url)
                chain.proceed(chain.request())
            }
        val builder =
            base
                .newBuilder()
                .addInterceptor(validation)
                .addNetworkInterceptor(validation)
        if (route != null) {
            val parts =
                ScopedTransportCache.getOrCreate(ScopedPartsKey(guard, base.transportKey())) {
                    routeParts(snapshot, base)
                }
            builder.connectionPool(parts.pool)
            if (snapshot.isLocal) {
                builder
                    .proxy(Proxy.NO_PROXY)
                    .dns(parts.dns)
                    .socketFactory(parts.sockets)
            }
        }
        return builder.build()
    }

    private fun routeParts(
        snapshot: ServerConnectionSnapshot,
        base: OkHttpClient,
    ): RouteTransportParts {
        if (!snapshot.isLocal) {
            return RouteTransportParts(
                base.dns,
                base.socketFactory,
                base.sslSocketFactory as? ClientCertificateSocketFactory,
            )
        }
        val network = requireNotNull(snapshot.network)
        val route = requireNotNull(snapshot.route)
        val dns =
            object : Dns {
                override fun lookup(hostname: String): List<InetAddress> =
                    network.getAllByName(dnsHostFor(route, hostname)).toList()
            }
        return RouteTransportParts(dns, network.socketFactory, base.sslSocketFactory as? ClientCertificateSocketFactory)
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
    val networkRevision: Long? = null,
)

internal fun ServerConnectionSnapshot.routeState() = RouteState(route, status, network, networkRevision)

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

private class RouteTransportParts(
    val dns: Dns,
    val sockets: SocketFactory,
    private val tlsSockets: ClientCertificateSocketFactory?,
    override val pool: ConnectionPool = ConnectionPool(),
) : ScopedTransportParts {
    override fun retire() {
        pool.evictAll()
        tlsSockets?.retireSessions()
    }
}
