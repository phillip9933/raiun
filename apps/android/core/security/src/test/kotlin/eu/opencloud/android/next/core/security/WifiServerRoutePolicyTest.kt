package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.TransportPolicyException
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class WifiServerRoutePolicyTest {
    private val route = WifiServerRoute("https://cloud.example/app", "Office", "https://192.168.1.20/app")

    @Test
    fun samePortAndPathRequired() {
        WifiServerRoutePolicy.validate(route)
        listOf(
            "http://192.168.1.20/app",
            "https://192.168.1.20:8443/app",
            "https://192.168.1.20/other",
            "https://user:pass@192.168.1.20/app",
            "https://192.168.1.20/app?token=secret",
            "https://192.168.1.20/app#fragment",
        ).forEach { local ->
            try {
                WifiServerRoutePolicy.validate(route.copy(localServerUrl = local))
                fail("Accepted $local")
            } catch (_: Exception) {
                // Every listed endpoint is outside the supported transport-only route.
            }
        }
    }

    @Test
    fun exactSsidAndWifiRequiredInEveryLocalMode() {
        val validated = WifiServerRoutePolicy.validate(route)
        val matching = WifiRouteObservation(true, true, false, "Office")
        assertEquals(WifiRouteStatus.ACTIVE, WifiServerRoutePolicy.status(validated, matching))
        assertEquals(
            WifiRouteStatus.ACTIVE,
            WifiServerRoutePolicy.status(validated.copy(mode = WifiRouteMode.LOCAL), matching),
        )
        assertEquals(
            WifiRouteStatus.DISABLED,
            WifiServerRoutePolicy.status(validated.copy(mode = WifiRouteMode.PUBLIC), matching),
        )
        assertEquals(
            WifiRouteStatus.SSID_MISMATCH,
            WifiServerRoutePolicy.status(validated.copy(mode = WifiRouteMode.LOCAL), matching.copy(ssid = "Guest")),
        )
        assertEquals(
            WifiRouteStatus.SSID_UNAVAILABLE,
            WifiServerRoutePolicy.status(validated, matching.copy(ssid = null)),
        )
        assertEquals(
            WifiRouteStatus.LOCATION_UNAVAILABLE,
            WifiServerRoutePolicy.status(validated, matching.copy(locationAvailable = false)),
        )
        assertEquals(WifiRouteStatus.NOT_WIFI, WifiServerRoutePolicy.status(validated, matching.copy(isVpn = true)))
        val spaced = WifiServerRoutePolicy.validate(route.copy(ssid = " Office "))
        assertEquals(WifiRouteStatus.ACTIVE, WifiServerRoutePolicy.status(spaced, matching.copy(ssid = " Office ")))
        assertEquals(WifiRouteStatus.SSID_MISMATCH, WifiServerRoutePolicy.status(spaced, matching))
    }

    @Test
    fun canonicalScopeNeverIncludesOtherOriginsOrSiblingPaths() {
        val validated = WifiServerRoutePolicy.validate(route)
        assertTrue(
            WifiServerRoutePolicy.isCanonicalRequest(validated, "https://cloud.example/app/dav/file".toHttpUrl()),
        )
        assertFalse(
            WifiServerRoutePolicy.isCanonicalRequest(validated, "https://cloud.example/application".toHttpUrl()),
        )
        assertFalse(WifiServerRoutePolicy.isCanonicalRequest(validated, "https://issuer.example/app/token".toHttpUrl()))
        assertFalse(WifiServerRoutePolicy.isCanonicalRequest(validated, "http://cloud.example/app".toHttpUrl()))
        assertEquals("192.168.1.20", dnsHostFor(validated, "cloud.example"))
        assertEquals("issuer.example", dnsHostFor(validated, "issuer.example"))
        assertTrue(isIncompatibleCanonicalOrigin(validated, "https://cloud.example:8443/app".toHttpUrl()))
        assertTrue(isIncompatibleCanonicalOrigin(validated, "http://cloud.example/app".toHttpUrl()))
        assertFalse(isIncompatibleCanonicalOrigin(validated, "https://issuer.example:8443/token".toHttpUrl()))
        try {
            requireCompatibleCanonicalOrigin(validated, "https://cloud.example:8443/app".toHttpUrl())
            fail("A same-host different-port request must be refused before transport")
        } catch (failure: TransportPolicyException) {
            assertEquals(OpenCloudError.Trust, failure.error)
        }
    }

    @Test
    fun staleNetworkOrConfigurationInvalidatesCapturedRoute() {
        val first = WifiServerRoutePolicy.validate(route)
        assertEquals(
            RouteState(first, WifiRouteStatus.ACTIVE, "network-1"),
            RouteState(first, WifiRouteStatus.ACTIVE, "network-1"),
        )
        assertFalse(
            RouteState(first, WifiRouteStatus.ACTIVE, "network-1") ==
                RouteState(first, WifiRouteStatus.ACTIVE, "network-2"),
        )
        assertFalse(
            RouteState(first, WifiRouteStatus.ACTIVE, "network-1") ==
                RouteState(
                    first.copy(local = "https://192.168.1.21/app".toHttpUrl()),
                    WifiRouteStatus.ACTIVE,
                    "network-1",
                ),
        )
        assertFalse(
            RouteState(first, WifiRouteStatus.SSID_MISMATCH, null) ==
                RouteState(first, WifiRouteStatus.ACTIVE, "network-1"),
        )
    }
}
