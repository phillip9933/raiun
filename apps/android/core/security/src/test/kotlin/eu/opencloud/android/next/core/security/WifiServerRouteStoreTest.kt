package eu.opencloud.android.next.core.security

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.TransportPolicyException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class WifiServerRouteStoreTest {
    @Test
    fun persistsModeByCanonicalServerAndRemovesIndependently() {
        val context: Context = RuntimeEnvironment.getApplication()
        val store = WifiServerRouteStore(context)
        val first =
            WifiServerRoute("https://cloud-one.example/", "Office", "https://192.168.1.10", mode = WifiRouteMode.LOCAL)
        val second = WifiServerRoute("https://cloud-two.example", "Home", "https://192.168.2.10")
        val nested = WifiServerRoute("https://nested.example/app/", "Office", "https://192.168.3.10/app/")
        store.put(first)
        store.put(second)
        store.put(nested)
        assertEquals(
            first.copy(canonicalServerUrl = "https://cloud-one.example"),
            WifiServerRouteStore(context).find("https://cloud-one.example"),
        )
        store.remove("https://cloud-one.example")
        assertNull(store.find(first.canonicalServerUrl))
        assertEquals(second, store.find(second.canonicalServerUrl))
        assertEquals(nested, store.find(nested.canonicalServerUrl))
        store.remove(second.canonicalServerUrl)
        store.remove(nested.canonicalServerUrl)
    }

    @Test
    fun malformedConfigurationFailsClosed() {
        val context: Context = RuntimeEnvironment.getApplication()
        val store = WifiServerRouteStore(context)
        val broken = WifiServerRoute("https://broken.example", "Office", "https://192.168.1.10")
        val unaffected = WifiServerRoute("https://healthy.example", "Office", "https://192.168.1.11")
        store.put(broken)
        store.put(unaffected)
        val file =
            File(context.noBackupFilesDir, "wifi-server-routes").listFiles()!!.first {
                it.readText().contains("broken.example")
            }
        file.writeText("{malformed")
        try {
            assertEquals(unaffected, store.find(unaffected.canonicalServerUrl))
            ServerConnectionRoute(context).createSnapshot(broken.canonicalServerUrl)
            org.junit.Assert.fail("Corrupt route configuration must refuse the request")
        } catch (failure: TransportPolicyException) {
            assertEquals(OpenCloudError.NetworkRouteChanged, failure.error)
        } finally {
            store.remove(broken.canonicalServerUrl)
            store.remove(unaffected.canonicalServerUrl)
        }
    }
}
