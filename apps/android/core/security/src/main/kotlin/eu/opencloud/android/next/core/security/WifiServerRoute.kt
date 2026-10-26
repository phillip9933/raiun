package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.network.EndpointPolicy
import okhttp3.HttpUrl

enum class WifiRouteMode { AUTOMATIC, PUBLIC, LOCAL }

/** A transport preference. The account and every HTTP request retain [canonicalServerUrl]. */
data class WifiServerRoute(
    val canonicalServerUrl: String,
    val ssid: String,
    val localServerUrl: String,
    val enabled: Boolean = true,
    val mode: WifiRouteMode = WifiRouteMode.AUTOMATIC,
)

data class ValidatedWifiServerRoute(
    val canonicalServerUrl: String,
    val canonical: HttpUrl,
    val local: HttpUrl,
    val ssid: String,
    val enabled: Boolean,
    val mode: WifiRouteMode,
)

enum class WifiRouteStatus {
    DISABLED,
    LOCATION_UNAVAILABLE,
    NOT_WIFI,
    SSID_UNAVAILABLE,
    SSID_MISMATCH,
    ACTIVE,
}

data class WifiRouteObservation(
    val locationAvailable: Boolean,
    val isWifi: Boolean,
    val isVpn: Boolean,
    val ssid: String?,
)

/** The local endpoint must be a different network address for the *same* HTTPS origin path and port. */
object WifiServerRoutePolicy {
    fun validate(route: WifiServerRoute): ValidatedWifiServerRoute {
        val canonical = EndpointPolicy().endpoint(route.canonicalServerUrl, allowQuery = false)
        val local = EndpointPolicy().endpoint(route.localServerUrl, allowQuery = false)
        require(canonical.username.isEmpty() && canonical.password.isEmpty())
        require(local.username.isEmpty() && local.password.isEmpty())
        require(canonical.encodedPath == local.encodedPath) { "Local path must match the canonical server path." }
        require(canonical.port == local.port) { "Local port must match the canonical server port." }
        require(canonical.host != local.host) { "Local address must differ from the canonical host." }
        val ssid = route.ssid
        require(ssid.isNotBlank() && ssid != "<unknown ssid>" && ssid.none(Char::isISOControl))
        return ValidatedWifiServerRoute(route.canonicalServerUrl, canonical, local, ssid, route.enabled, route.mode)
    }

    fun status(
        route: ValidatedWifiServerRoute?,
        observed: WifiRouteObservation,
    ): WifiRouteStatus =
        when {
            route == null || !route.enabled || route.mode == WifiRouteMode.PUBLIC -> WifiRouteStatus.DISABLED
            !observed.locationAvailable -> WifiRouteStatus.LOCATION_UNAVAILABLE
            !observed.isWifi || observed.isVpn -> WifiRouteStatus.NOT_WIFI
            observed.ssid.isNullOrBlank() || observed.ssid == "<unknown ssid>" -> WifiRouteStatus.SSID_UNAVAILABLE
            observed.ssid != route.ssid -> WifiRouteStatus.SSID_MISMATCH
            else -> WifiRouteStatus.ACTIVE
        }

    fun isCanonicalRequest(
        route: ValidatedWifiServerRoute,
        url: HttpUrl,
    ): Boolean {
        if (!url.isHttps || url.host != route.canonical.host || url.port != route.canonical.port) return false
        val basePath = route.canonical.encodedPath.trimEnd('/')
        return url.encodedPath == basePath || url.encodedPath.startsWith("$basePath/")
    }
}
