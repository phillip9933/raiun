package eu.opencloud.android.next.core.security

import android.Manifest
import android.app.Application
import android.content.Context
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.NetworkInfo
import android.net.wifi.WifiManager
import eu.opencloud.android.next.core.network.HttpClients
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CertificatePinner
import okhttp3.Dispatcher
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetworkInfo
import org.robolectric.shadows.ShadowWifiInfo
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

@RunWith(RobolectricTestRunner::class)
class ScopedTransportReuseTest {
    @get:Rule val temporary = TemporaryFolder()

    @After fun retireTestTransports() = ScopedTransportCache.invalidateAll()

    @Test fun `independent clients reuse all TLS parts and preserve cancellation and request policies`() {
        val source = FakeIdentitySource(identity("synthetic-client-cert.pem"))
        val directory = temporary.newFolder()
        val policy = ClientCertificatePolicy(directory, source)
        policy.save(SERVER, listOf(ORIGIN), "test")
        val firstBase = HttpClients.newBuilder().readTimeout(4, TimeUnit.SECONDS).build()
        val secondBase = HttpClients.newBuilder().readTimeout(9, TimeUnit.SECONDS).build()
        val first = policy.applyTo(firstBase, SERVER)
        val second = ClientCertificatePolicy(directory, source).applyTo(secondBase, SERVER)
        assertSame(first.connectionPool, second.connectionPool)
        assertSame(first.sslSocketFactory, second.sslSocketFactory)
        assertSame(first.x509TrustManager, second.x509TrustManager)
        assertNotSame(first.dispatcher, second.dispatcher)
        assertSame(firstBase.dispatcher, first.dispatcher)
        assertSame(secondBase.dispatcher, second.dispatcher)
        assertEquals(4_000, first.readTimeoutMillis)
        assertEquals(9_000, second.readTimeoutMillis)
        assertIndependentCancellation(first, second)
        assertFalse(first.followRedirects)
        assertFalse(second.followSslRedirects)
    }

    @Test
    @Config(sdk = [28])
    fun `composed TLS policy reuses certificate and active local route transports across owners`() {
        val context = RuntimeEnvironment.getApplication()
        configureLocalWifi(context)
        val store = WifiServerRouteStore(context)
        store.put(WifiServerRoute(SERVER, "Synthetic Wi-Fi", "https://192.0.2.10"))
        val source = FakeIdentitySource(identity("synthetic-client-cert.pem"))
        val certificates = ClientCertificatePolicy(temporary.newFolder(), source)
        certificates.save(SERVER, listOf(ORIGIN), "test")
        val policy = TlsPolicy(context, certificates)
        val firstBase = HttpClients.newBuilder().readTimeout(4, TimeUnit.SECONDS).build()
        val secondBase = HttpClients.newBuilder().readTimeout(9, TimeUnit.SECONDS).build()
        try {
            assertTrue(ServerConnectionRoute(context).createSnapshot(SERVER).isLocal)
            val first = policy.applyTo(firstBase, SERVER)
            val second = policy.applyTo(secondBase, SERVER)
            assertSame(first.connectionPool, second.connectionPool)
            assertSame(first.dns, second.dns)
            assertNotSame(firstBase.dns, first.dns)
            assertSame(first.socketFactory, second.socketFactory)
            assertSame(first.sslSocketFactory, second.sslSocketFactory)
            assertSame(first.x509TrustManager, second.x509TrustManager)
            assertEquals(first.certificatePinner, second.certificatePinner)
            assertSame(firstBase.dispatcher, first.dispatcher)
            assertSame(secondBase.dispatcher, second.dispatcher)
            assertNotSame(first.dispatcher, second.dispatcher)
            assertEquals(4_000, first.readTimeoutMillis)
            assertEquals(9_000, second.readTimeoutMillis)
        } finally {
            store.remove(SERVER)
        }
    }

    @Test fun `certificate derived clients actually reuse one HTTP connection`() {
        val source = FakeIdentitySource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder(), source)
        policy.save(SERVER, listOf(ORIGIN), "test")
        val base = OkHttpClient.Builder().readTimeout(3, TimeUnit.SECONDS).build()
        val first = policy.applyTo(base.newBuilder().dispatcher(Dispatcher()).build(), SERVER)
        val second = policy.applyTo(base.newBuilder().dispatcher(Dispatcher()).build(), SERVER)
        val executor = Executors.newSingleThreadExecutor()
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 3_000
            val exchange =
                executor.submit<Int> {
                    server.accept().use { socket ->
                        socket.soTimeout = 3_000
                        val input = socket.getInputStream().bufferedReader(Charsets.US_ASCII)
                        repeat(2) {
                            var line = input.readLine()
                            while (!line.isNullOrEmpty()) line = input.readLine()
                            val response =
                                "HTTP/1.1 200 OK\r\n" +
                                    "Content-Length: 2\r\n" +
                                    "\r\nOK"
                            socket.getOutputStream().write(response.toByteArray())
                            socket.getOutputStream().flush()
                        }
                    }
                    2
                }
            try {
                val request = Request.Builder().url("http://127.0.0.1:${server.localPort}/").build()
                first.newCall(request).execute().use { assertEquals("OK", it.body?.string()) }
                second.newCall(request).execute().use { assertEquals("OK", it.body?.string()) }
                assertEquals(2, exchange.get(5, TimeUnit.SECONDS))
            } finally {
                executor.shutdownNow()
            }
        }
    }

    @Test fun `custom base trust policies and fake identity sources never share transports`() {
        val source = FakeIdentitySource(identity("synthetic-client-cert.pem"))
        val directory = temporary.newFolder()
        val policy = ClientCertificatePolicy(directory, source)
        policy.save(SERVER, listOf(ORIGIN), "test")
        val base = OkHttpClient()
        val first = policy.applyTo(base, SERVER)
        val customVerifier = base.newBuilder().hostnameVerifier { _, _ -> false }.build()
        val pinned =
            base
                .newBuilder()
                .certificatePinner(
                    CertificatePinner
                        .Builder()
                        .add(
                            "idp.example.test",
                            "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        ).build(),
                ).build()
        assertNotSame(first.connectionPool, policy.applyTo(customVerifier, SERVER).connectionPool)
        assertNotSame(first.sslSocketFactory, policy.applyTo(pinned, SERVER).sslSocketFactory)
        val otherSource = FakeIdentitySource(source.identity)
        assertNotSame(
            first.connectionPool,
            ClientCertificatePolicy(directory, otherSource).applyTo(base, SERVER).connectionPool,
        )
    }

    @Test fun `absent binding install replacement removal and ABA revoke only their own server`() {
        val source = FakeIdentitySource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder(), source)
        val base = OkHttpClient()
        val initiallyAbsent = policy.applyTo(base, SERVER)
        policy.save(SERVER, listOf(ORIGIN), "test")
        refused(initiallyAbsent)
        val first = policy.applyTo(base, SERVER)
        policy.save("https://unrelated.example.test", listOf(ORIGIN), "test")
        val unrelated = policy.applyTo(base, "https://unrelated.example.test")
        policy.clear(SERVER)
        policy.save(SERVER, listOf(ORIGIN), "test")
        refused(first)
        val next = policy.applyTo(base, SERVER)
        assertNotSame(first.sslSocketFactory, next.sslSocketFactory)
        assertSame(unrelated.connectionPool, policy.applyTo(base, "https://unrelated.example.test").connectionPool)
        source.identity = identity("synthetic-client-cert-2.pem")
        assertThrows(ClientCertificateException.Changed::class.java) { policy.applyTo(base, SERVER) }
        source.identity = identity("synthetic-client-cert.pem")
        refused(next)
    }

    @Test fun `unavailable and expired identities on cache hit retire old guards after restoration`() {
        val original = identity("synthetic-client-cert.pem")
        val source = FakeIdentitySource(original)
        val policy = ClientCertificatePolicy(temporary.newFolder(), source)
        policy.save(SERVER, listOf(ORIGIN), "test")
        val base = OkHttpClient()
        val beforeUnavailable = policy.applyTo(base, SERVER)
        source.available = false
        assertThrows(ClientCertificateException.Unavailable::class.java) { policy.applyTo(base, SERVER) }
        source.available = true
        refused(beforeUnavailable)
        val beforeExpired = policy.applyTo(base, SERVER)
        // Alter only the public synthetic fixture's DER validity date. It is never used for a handshake.
        val expiredDer =
            String(original.chain[0].encoded, Charsets.ISO_8859_1)
                .replace("361023130749Z", "261025130749Z")
                .toByteArray(Charsets.ISO_8859_1)
        val expired =
            CertificateFactory
                .getInstance("X.509")
                .generateCertificate(expiredDer.inputStream()) as X509Certificate
        assertThrows(java.security.cert.CertificateExpiredException::class.java) { expired.checkValidity() }
        source.identity = original.copy(chain = arrayOf(expired))
        assertThrows(ClientCertificateException.Unavailable::class.java) { policy.applyTo(base, SERVER) }
        source.identity = original
        refused(beforeExpired)
    }

    @Test fun `route token isolates TLS contexts across network admission ABA`() {
        val source = FakeIdentitySource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder(), source)
        policy.save(SERVER, listOf(ORIGIN), "test")
        val base = OkHttpClient()
        val scope = Any()
        val firstRoute = ScopedTransportCache.guard(scope, "network A")
        val first = policy.applyTo(base, SERVER, firstRoute)
        assertSame(first.sslSocketFactory, policy.applyTo(base, SERVER, firstRoute).sslSocketFactory)
        ScopedTransportCache.guard(scope, "network B")
        val nextRoute = ScopedTransportCache.guard(scope, "network A")
        assertFalse(firstRoute.isCurrent())
        assertNotSame(first.sslSocketFactory, policy.applyTo(base, SERVER, nextRoute).sslSocketFactory)
    }

    @Test fun `LRU bounds resource entries without revoking current guards`() {
        val base = OkHttpClient()
        val guard = ScopedTransportCache.guard(Any(), "current")
        val oldest = ScopedTransportCache.getOrCreate(ScopedPartsKey(guard, base.transportKey())) { FakeParts() }
        repeat(ScopedTransportCache.MAX_ENTRIES + 3) {
            val next = ScopedTransportCache.guard(Any(), "current")
            ScopedTransportCache.getOrCreate(ScopedPartsKey(next, base.transportKey())) { FakeParts() }
        }
        assertTrue(oldest.retired)
        assertTrue(guard.isCurrent())
        assertEquals(ScopedTransportCache.MAX_ENTRIES, ScopedTransportCache.size())
    }

    @Suppress("DEPRECATION") // API 28 fixture exercises the supported legacy SSID observation path.
    private fun configureLocalWifi(context: Application) {
        Shadows.shadowOf(context).grantPermissions(Manifest.permission.ACCESS_FINE_LOCATION)
        val location = context.getSystemService(Context.LOCATION_SERVICE) as LocationManager
        Shadows.shadowOf(location).setLocationEnabled(true)
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val networkInfo =
            ShadowNetworkInfo.newInstance(
                NetworkInfo.DetailedState.CONNECTED,
                ConnectivityManager.TYPE_WIFI,
                0,
                true,
                true,
            )
        Shadows.shadowOf(connectivity).setActiveNetworkInfo(networkInfo)
        val capabilities = NetworkCapabilities()
        Shadows.shadowOf(capabilities).addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        Shadows.shadowOf(connectivity).setNetworkCapabilities(requireNotNull(connectivity.activeNetwork), capabilities)
        val wifi = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val info = ShadowWifiInfo.newInstance()
        Shadows.shadowOf(info).setSSID("Synthetic Wi-Fi")
        Shadows.shadowOf(wifi).setConnectionInfo(info)
    }

    private fun assertIndependentCancellation(
        first: OkHttpClient,
        second: OkHttpClient,
    ) {
        val entered = CountDownLatch(2)
        val release = CountDownLatch(1)
        val completed = CountDownLatch(2)
        val secondStatus = AtomicInteger()
        val blocker =
            Interceptor { chain ->
                entered.countDown()
                if (!release.await(5, TimeUnit.SECONDS)) throw IOException("Synthetic call release timed out")
                Response
                    .Builder()
                    .request(chain.request())
                    .protocol(okhttp3.Protocol.HTTP_1_1)
                    .code(200)
                    .message("OK")
                    .body("OK".toResponseBody())
                    .build()
            }
        val request = Request.Builder().url(ORIGIN).build()
        val firstCall =
            first
                .newBuilder()
                .addInterceptor(blocker)
                .build()
                .newCall(request)
        val secondCall =
            second
                .newBuilder()
                .addInterceptor(blocker)
                .build()
                .newCall(request)
        val callback =
            object : Callback {
                override fun onFailure(
                    call: Call,
                    e: IOException,
                ) {
                    if (call === secondCall) secondStatus.set(-1)
                    completed.countDown()
                }

                override fun onResponse(
                    call: Call,
                    response: Response,
                ) {
                    response.use { if (call === secondCall) secondStatus.set(it.code) }
                    completed.countDown()
                }
            }
        firstCall.enqueue(callback)
        secondCall.enqueue(callback)
        try {
            assertTrue("Both calls must be registered and running", entered.await(3, TimeUnit.SECONDS))
            first.dispatcher.cancelAll()
            assertTrue(firstCall.isCanceled())
            assertFalse(secondCall.isCanceled())
        } finally {
            release.countDown()
            assertTrue("Both callbacks must finish", completed.await(3, TimeUnit.SECONDS))
        }
        assertEquals(200, secondStatus.get())
    }

    private fun refused(client: OkHttpClient) {
        assertThrows(ClientCertificateException.Changed::class.java) {
            client.newCall(Request.Builder().url(ORIGIN).build()).execute().close()
        }
    }

    private fun identity(resource: String): ClientIdentity {
        val certificate =
            requireNotNull(javaClass.classLoader?.getResourceAsStream(resource)).use {
                CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
            }
        val key =
            object : PrivateKey {
                override fun getAlgorithm(): String = "RSA"

                override fun getFormat(): String = "PKCS#8"

                override fun getEncoded(): ByteArray = byteArrayOf()
            }
        return ClientIdentity(key, arrayOf(certificate))
    }

    private class FakeIdentitySource(
        var identity: ClientIdentity,
    ) : ClientIdentitySource {
        var available = true

        override fun load(alias: String): ClientIdentity? = if (available) identity else null
    }

    private class FakeParts : ScopedTransportParts {
        override val pool = okhttp3.ConnectionPool()
        var retired = false

        override fun retire() {
            retired = true
        }
    }

    private companion object {
        const val SERVER = "https://cloud.example.test"
        const val ORIGIN = "https://idp.example.test"
    }
}
