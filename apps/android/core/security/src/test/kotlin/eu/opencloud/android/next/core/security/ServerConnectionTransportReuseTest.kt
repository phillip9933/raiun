package eu.opencloud.android.next.core.security

import eu.opencloud.android.next.core.network.TransportPolicyException
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.shadows.ShadowNetwork

@RunWith(RobolectricTestRunner::class)
class ServerConnectionTransportReuseTest {
    private val context get() = RuntimeEnvironment.getApplication()

    @After fun retireTransports() = ScopedTransportCache.invalidateAll()

    @Test fun `unchanged route retains DNS socket factory and pool with independent caller dispatchers`() {
        val router = ServerConnectionRoute(context)
        val route = WifiServerRoutePolicy.validate(route())
        val network = ShadowNetwork.newInstance(31)
        val snapshot = ServerConnectionSnapshot(route, WifiRouteStatus.ACTIVE, network)
        val base = OkHttpClient()
        val firstBase = base.newBuilder().dispatcher(okhttp3.Dispatcher()).build()
        val secondBase = base.newBuilder().dispatcher(okhttp3.Dispatcher()).build()
        val first = router.applyTo(firstBase, snapshot)
        val second = ServerConnectionRoute(context).applyTo(secondBase, snapshot.copy())
        assertSame(first.connectionPool, second.connectionPool)
        assertSame(first.dns, second.dns)
        assertSame(first.socketFactory, second.socketFactory)
        assertSame(first.sslSocketFactory, second.sslSocketFactory)
        assertSame(firstBase.dispatcher, first.dispatcher)
        assertSame(secondBase.dispatcher, second.dispatcher)
        assertNotSame(first.dispatcher, second.dispatcher)
        val changed = router.applyTo(base, snapshot.copy(network = ShadowNetwork.newInstance(32)))
        assertNotSame(first.connectionPool, changed.connectionPool)
        assertNotSame(first.dns, changed.dns)
        assertNotSame(first.socketFactory, changed.socketFactory)
    }

    @Test fun `route store install remove and ABA revoke original clients without affecting other servers`() {
        val store = WifiServerRouteStore(context)
        val router = ServerConnectionRoute(context, store)
        val base = OkHttpClient()
        val absent = router.applyTo(base, router.createSnapshot(SERVER))
        val public = route().copy(mode = WifiRouteMode.PUBLIC)
        store.put(public)
        refused(absent)
        val first = router.applyTo(base, router.createSnapshot(SERVER))
        val other = public.copy(canonicalServerUrl = "https://other.example.test")
        store.put(other)
        val unaffected = router.applyTo(base, router.createSnapshot(other.canonicalServerUrl))
        try {
            store.remove(SERVER)
            store.put(public)
            refused(first)
            assertNotSame(first.connectionPool, router.applyTo(base, router.createSnapshot(SERVER)).connectionPool)
            assertSame(
                unaffected.connectionPool,
                router.applyTo(base, router.createSnapshot(other.canonicalServerUrl)).connectionPool,
            )
        } finally {
            store.remove(SERVER)
            store.remove(other.canonicalServerUrl)
        }
    }

    @Test fun `observed route loss revokes original admission even after network ABA`() {
        val router = ServerConnectionRoute(context)
        val route = WifiServerRoutePolicy.validate(route())
        val network = ShadowNetwork.newInstance(41)
        val snapshot = ServerConnectionSnapshot(route, WifiRouteStatus.ACTIVE, network)
        val first = router.applyTo(OkHttpClient(), snapshot)
        val scope = WifiServerRouteStore(context).transportScope(SERVER)
        val oldGuard = ScopedTransportCache.guard(scope, snapshot.routeState())
        ScopedTransportCache.revokeRouteNetwork(network)
        assertFalse(oldGuard.isCurrent())
        val next = router.applyTo(OkHttpClient(), snapshot.copy())
        assertNotSame(first.connectionPool, next.connectionPool)
        assertNotSame(first.dns, next.dns)
    }

    @Test fun `captured observation cannot publish after observed network loss and restoration`() {
        val monitor = WifiServerNetworkMonitor.shared(context)
        val network = ShadowNetwork.newInstance(51)
        val field = WifiServerNetworkMonitor::class.java.getDeclaredField("callback").apply { isAccessible = true }
        val callback = field.get(monitor) as android.net.ConnectivityManager.NetworkCallback
        callback.onAvailable(network)
        val capturedRevision = monitor.capture().second
        val route = WifiServerRoutePolicy.validate(route())
        val snapshot = ServerConnectionSnapshot(route, WifiRouteStatus.ACTIVE, network, SERVER, capturedRevision)
        callback.onLost(network)
        callback.onAvailable(network)
        // The old snapshot has not acquired a guard yet: it must not acquire a fresh guard after ABA.
        assertNull(monitor.admit(capturedRevision, Any(), snapshot.routeState()))
    }

    @Test fun `permission ABA before first callback invalidates a captured route revision`() {
        val monitor = WifiServerNetworkMonitor.shared(context)
        val method =
            WifiServerNetworkMonitor::class.java
                .getDeclaredMethod(
                    "ensureRegistration",
                    Boolean::class.javaPrimitiveType,
                ).apply { isAccessible = true }
        method.invoke(monitor, true)
        val revisionField =
            WifiServerNetworkMonitor::class.java
                .getDeclaredField("observationRevision")
                .apply { isAccessible = true }
        val revision = (revisionField.get(monitor) as java.util.concurrent.atomic.AtomicLong).get()
        method.invoke(monitor, false)
        method.invoke(monitor, true)
        val snapshot =
            ServerConnectionSnapshot(
                WifiServerRoutePolicy.validate(route()),
                WifiRouteStatus.ACTIVE,
                ShadowNetwork.newInstance(61),
                SERVER,
                revision,
            )
        assertNull(monitor.admit(revision, Any(), snapshot.routeState()))
    }

    private fun refused(client: OkHttpClient) {
        assertThrows(TransportPolicyException::class.java) {
            client.newCall(Request.Builder().url(SERVER).build()).execute().close()
        }
    }

    private fun route() = WifiServerRoute(SERVER, "Synthetic Wi-Fi", "https://192.0.2.10")

    private companion object {
        const val SERVER = "https://cloud.example.test"
    }
}
