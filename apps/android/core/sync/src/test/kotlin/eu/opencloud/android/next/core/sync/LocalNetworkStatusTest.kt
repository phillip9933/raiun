package eu.opencloud.android.next.core.sync

import android.net.NetworkCapabilities
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class LocalNetworkStatusTest {
    @Test fun `local wifi and ethernet do not need internet or validation`() {
        listOf(
            NetworkCapabilities.TRANSPORT_WIFI,
            NetworkCapabilities.TRANSPORT_ETHERNET,
            NetworkCapabilities.TRANSPORT_VPN,
        ).forEach { transport ->
            val capabilities = NetworkCapabilities()
            org.robolectric.Shadows.shadowOf(capabilities).apply {
                addTransportType(transport)
                removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                removeCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            }
            assertTrue(supportsServerTraffic(capabilities))
        }
    }

    @Test fun `no network remains offline while ordinary internet networks work`() {
        assertFalse(supportsServerTraffic(null))
        assertFalse(supportsServerTraffic(NetworkCapabilities()))
        val internet = NetworkCapabilities()
        org.robolectric.Shadows
            .shadowOf(internet)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        assertTrue(supportsServerTraffic(internet))
    }
}
