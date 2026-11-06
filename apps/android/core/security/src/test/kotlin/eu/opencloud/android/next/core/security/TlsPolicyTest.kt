package eu.opencloud.android.next.core.security

import android.content.Context
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransportPolicyException
import okhttp3.CertificatePinner
import okhttp3.CipherSuite
import okhttp3.Connection
import okhttp3.Handshake
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.TlsVersion
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.lang.reflect.Proxy
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35], shadows = [DirectoryAwareLinuxShadow::class])
class TlsPolicyTest {
    @get:Rule val directoryModel = DirectoryLinuxModelRule()
    private val context: Context = RuntimeEnvironment.getApplication()

    @Test fun `OkHttp underscore host receives persisted pin policy`() {
        val serverUrl = "https://CLOUD_ONE.example.test:8443/cloud/"
        val host = EndpointPolicy().endpoint(serverUrl).host
        context
            .getSharedPreferences("tls_trust", Context.MODE_PRIVATE)
            .edit()
            .putStringSet("pins.$host", setOf("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
            .commit()

        val certificate = syntheticCertificate()
        val trustStore =
            KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null, null)
                setCertificateEntry("synthetic", certificate)
            }
        val trustFactory =
            TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
                init(trustStore)
            }
        val tls = SSLContext.getInstance("TLS").apply { init(null, trustFactory.trustManagers, null) }
        val trust = trustFactory.trustManagers.filterIsInstance<X509TrustManager>().single()
        val base = OkHttpClient.Builder().sslSocketFactory(tls.socketFactory, trust).build()
        val client = TlsPolicy(context).applyTo(base, serverUrl)

        assertSame(base.certificatePinner, client.certificatePinner)
        assertSame(base.sslSocketFactory, client.sslSocketFactory)
        assertSame(base.hostnameVerifier, client.hostnameVerifier)
        var transmitted = false
        val failure =
            assertThrows(TransportPolicyException::class.java) {
                client.networkInterceptors.last().intercept(
                    pinChain(serverUrl, certificate) { transmitted = true },
                )
            }
        assertEquals(OpenCloudError.Trust, failure.error)
        assertFalse(transmitted)
        client.networkInterceptors
            .last()
            .intercept(
                pinChain("https://other.example.test", certificate) { transmitted = true },
            ).close()
        assertTrue(transmitted)
    }

    @Test fun `matching legacy pin permits transmission while retaining the required base pinner`() {
        val certificate = syntheticCertificate()
        val host = "cloud_one.example.test"
        val url = "https://$host"
        context
            .getSharedPreferences("tls_trust", Context.MODE_PRIVATE)
            .edit()
            .putStringSet("pins.$host", setOf(CertificatePinner.pin(certificate)))
            .commit()
        val basePinner =
            CertificatePinner
                .Builder()
                .add(
                    host,
                    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ).build()
        val base = OkHttpClient.Builder().certificatePinner(basePinner).build()
        val client = TlsPolicy(context).applyTo(base, url)
        var transmitted = false

        client.networkInterceptors
            .last()
            .intercept(pinChain(url, certificate) { transmitted = true })
            .close()

        assertTrue(transmitted)
        assertSame(base.certificatePinner, client.certificatePinner)
        assertThrows(javax.net.ssl.SSLPeerUnverifiedException::class.java) {
            client.certificatePinner.check(host, listOf(certificate))
        }
    }

    @Test fun `cached legacy transport refuses changed policy before transmission`() {
        val certificate = syntheticCertificate()
        val host = "cloud_one.example.test"
        val url = "https://$host"
        val preferences = context.getSharedPreferences("tls_trust", Context.MODE_PRIVATE)
        preferences.edit().putStringSet("pins.$host", setOf(CertificatePinner.pin(certificate))).commit()
        val client = TlsPolicy(context).applyTo(OkHttpClient(), url)
        preferences
            .edit()
            .putStringSet(
                "pins.$host",
                setOf("sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            ).commit()
        var transmitted = false

        val failure =
            assertThrows(TransportPolicyException::class.java) {
                client.networkInterceptors.last().intercept(pinChain(url, certificate) { transmitted = true })
            }

        assertEquals(OpenCloudError.Trust, failure.error)
        assertFalse(transmitted)
    }

    @Test fun `legacy pinned WebSocket upgrade is refused before transmission`() {
        val certificate = syntheticCertificate()
        val host = "cloud_one.example.test"
        val url = "https://$host"
        context
            .getSharedPreferences("tls_trust", Context.MODE_PRIVATE)
            .edit()
            .putStringSet("pins.$host", setOf(CertificatePinner.pin(certificate)))
            .commit()
        val client = TlsPolicy(context).applyTo(OkHttpClient(), url)
        var transmitted = false

        val failure =
            assertThrows(TransportPolicyException::class.java) {
                client.interceptors.last().intercept(pinChain(url, certificate, "WebSocket") { transmitted = true })
            }

        assertEquals(OpenCloudError.Trust, failure.error)
        assertFalse(transmitted)
    }

    @Test fun `OkHttp underscore host receives scoped client identity transport`() {
        val certificate = syntheticCertificate()
        val key =
            object : PrivateKey {
                override fun getAlgorithm(): String = "RSA"

                override fun getFormat(): String = "PKCS#8"

                override fun getEncoded(): ByteArray = byteArrayOf()
            }
        val identity = ClientIdentity(key, arrayOf(certificate))
        val source =
            object : ClientIdentitySource {
                override fun load(alias: String): ClientIdentity = identity
            }
        val configured = "https://cloud_one.example.test:8443/cloud"
        val policy = ClientCertificatePolicy(File(context.noBackupFilesDir, "client-certificates"), source)
        policy.save(configured, listOf("https://idp_one.example.test:9443"), "test-alias")
        val base = OkHttpClient()

        val client = TlsPolicy(context, policy).applyTo(base, "https://CLOUD_ONE.example.test:8443/cloud/")

        assertEquals(listOf(Protocol.HTTP_1_1), client.protocols)
        assertFalse(base.connectionPool === client.connectionPool)
        assertFalse(client.followRedirects)
        assertFalse(client.followSslRedirects)
        assertEquals(3, client.interceptors.size)
    }

    @Test fun `OkHttp underscore host cannot bypass corrupt Wi-Fi route policy`() {
        val serverUrl = "https://cloud_one.example.test:8443/cloud/"
        val store = WifiServerRouteStore(context)
        store.put(WifiServerRoute(serverUrl, "Office", "https://192.168.1.10:8443/cloud/"))
        File(context.noBackupFilesDir, "wifi-server-routes")
            .listFiles()!!
            .single()
            .writeText("{malformed")

        val failure =
            assertThrows(TransportPolicyException::class.java) {
                TlsPolicy(context).applyTo(OkHttpClient(), serverUrl)
            }

        assertEquals(OpenCloudError.NetworkRouteChanged, failure.error)
    }

    @Test fun `invalid nonempty configured URLs fail closed`() {
        val policy = TlsPolicy(context)
        val base = OkHttpClient()
        listOf(
            " ",
            "cloud_one.example.test",
            "https://",
            "http://cloud_one.example.test",
            "https://user:password@cloud_one.example.test",
            "https://cloud_one.example.test?query",
            "https://cloud_one.example.test#fragment",
        ).forEach { serverUrl ->
            val failure = assertThrows(OpenCloudException::class.java) { policy.applyTo(base, serverUrl) }
            assertEquals(OpenCloudError.Trust, failure.error)
        }
    }

    @Test fun `empty server preserves intentional authentication bootstrap client`() {
        val base = OkHttpClient.Builder().followRedirects(false).build()

        assertSame(base, TlsPolicy(context).applyTo(base, ""))
    }

    /** A checked synthetic connection: proceeding represents the first possible HTTP transmission. */
    private fun pinChain(
        url: String,
        certificate: X509Certificate,
        upgrade: String? = null,
        onProceed: () -> Unit,
    ): Interceptor.Chain {
        val request =
            Request
                .Builder()
                .url(url)
                .apply { if (upgrade != null) header("Upgrade", upgrade) }
                .build()
        val handshake =
            Handshake.get(
                TlsVersion.TLS_1_2,
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                listOf(certificate),
                emptyList(),
            )
        val connection =
            Proxy.newProxyInstance(
                Connection::class.java.classLoader,
                arrayOf(Connection::class.java),
            ) { _, method, _ ->
                check(method.name == "handshake")
                handshake
            } as Connection
        return Proxy.newProxyInstance(
            Interceptor.Chain::class.java.classLoader,
            arrayOf(Interceptor.Chain::class.java),
        ) { _, method, _ ->
            when (method.name) {
                "request" -> request
                "connection" -> connection
                "proceed" -> {
                    onProceed()
                    Response
                        .Builder()
                        .request(request)
                        .protocol(Protocol.HTTP_1_1)
                        .code(200)
                        .message("OK")
                        .body("".toResponseBody())
                        .build()
                }
                else -> error("Unexpected synthetic chain call")
            }
        } as Interceptor.Chain
    }

    private fun syntheticCertificate(): X509Certificate =
        requireNotNull(javaClass.classLoader?.getResourceAsStream("synthetic-client-cert.pem")).use {
            CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
        }
}
