package eu.opencloud.android.next.core.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

/** Default Android TLS providers with disposable synthetic test-only certificates. */
@RunWith(AndroidJUnit4::class)
class ClientCertificateTlsAndroidTest {
    private val password = "synthetic-test-only".toCharArray()

    @Test fun clientCertificateIsSentOnlyToItsConfiguredOrigin() {
        val clientStore = fixture("synthetic-mtls-client.p12.b64")
        val serverStore = fixture("synthetic-mtls-server.p12.b64")
        val clientCertificate = clientStore.getCertificate("client") as X509Certificate
        val serverCertificate = serverStore.getCertificate("server") as X509Certificate
        val identity =
            ClientIdentity(
                clientStore.getKey("client", password) as java.security.PrivateKey,
                clientStore.getCertificateChain("client").map { it as X509Certificate }.toTypedArray(),
            )
        val source =
            object : ClientIdentitySource {
                override fun load(alias: String): ClientIdentity? = if (alias == "client") identity else null
            }
        val serverContext =
            SSLContext.getInstance("TLS").apply {
                init(keyManagers(serverStore), trustManagers(clientCertificate), null)
            }

        handshake(serverContext, serverCertificate, clientCertificate, source, configured = true)
        handshake(serverContext, serverCertificate, clientCertificate, source, configured = false)
    }

    @Suppress("NestedBlockDepth")
    private fun handshake(
        serverContext: SSLContext,
        serverCertificate: X509Certificate,
        clientCertificate: X509Certificate,
        source: ClientIdentitySource,
        configured: Boolean,
    ) {
        val server =
            serverContext.serverSocketFactory.createServerSocket(
                0,
                1,
                InetAddress.getByName("127.0.0.1"),
            ) as SSLServerSocket
        val protocol = if ("TLSv1.3" in server.supportedProtocols) "TLSv1.3" else "TLSv1.2"
        server.enabledProtocols = arrayOf(protocol)
        server.needClientAuth = true
        server.soTimeout = 5_000
        val port = server.localPort
        val origin = if (configured) "https://localhost:$port" else "https://different.example.test:$port"
        val binding =
            ClientCertificateBinding(
                "https://cloud.example.test",
                setOf(origin),
                "client",
                sha256(clientCertificate.encoded),
            )
        val peers = ClientCertificatePeerRegistry()
        val clientContext =
            SSLContext.getInstance("TLS").apply {
                init(
                    arrayOf(ScopedKeyManager(binding, source, peers) { binding }),
                    trustManagers(serverCertificate),
                    null,
                )
            }
        val socketFactory = ClientCertificateSocketFactory(clientContext.socketFactory, peers)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val peerCertificate =
                executor.submit<X509Certificate?> {
                    server.use { listener ->
                        (listener.accept() as SSLSocket).use { socket ->
                            socket.soTimeout = 5_000
                            socket.enabledProtocols = arrayOf(protocol)
                            val serverHandshake =
                                runCatching {
                                    socket.startHandshake()
                                    val peer = socket.session.peerCertificates.firstOrNull() as? X509Certificate
                                    socket.outputStream.write(7)
                                    socket.outputStream.flush()
                                    if (socket.inputStream.read() !=
                                        8
                                    ) {
                                        throw java.io.IOException("Synthetic TLS acknowledgement missing")
                                    }
                                    peer
                                }
                            if (configured) serverHandshake.getOrThrow() else serverHandshake.getOrNull()
                        }
                    }
                }
            val clientHandshake =
                Socket("127.0.0.1", port).use { transport ->
                    val tlsSocket =
                        socketFactory.createSocket(
                            transport,
                            "localhost",
                            port,
                            true,
                        ) as SSLSocket
                    tlsSocket.use { socket ->
                        socket.soTimeout = 5_000
                        socket.enabledProtocols = arrayOf(protocol)
                        val parameters = socket.sslParameters
                        parameters.endpointIdentificationAlgorithm = "HTTPS"
                        socket.sslParameters = parameters
                        runCatching {
                            socket.startHandshake()
                            assertEquals(protocol, socket.session.protocol)
                            socket.inputStream.read().also { if (it == 7) socket.outputStream.write(8) }
                        }
                    }
                }
            val peer = peerCertificate.get(10, TimeUnit.SECONDS)
            if (configured) {
                assertEquals(7, clientHandshake.getOrThrow())
                assertArrayEquals(
                    clientCertificate.encoded,
                    requireNotNull(peer).encoded,
                )
            } else {
                assertNull(peer)
            }
        } finally {
            server.close()
            executor.shutdownNow()
        }
    }

    private fun fixture(name: String): KeyStore =
        KeyStore.getInstance("PKCS12").apply {
            InstrumentationRegistry
                .getInstrumentation()
                .context.assets
                .open(name)
                .use { encoded ->
                    Base64.getMimeDecoder().wrap(encoded).use { decoded ->
                        load(decoded, password)
                    }
                }
        }

    private fun keyManagers(store: KeyStore) =
        KeyManagerFactory
            .getInstance(KeyManagerFactory.getDefaultAlgorithm())
            .apply {
                init(store, password)
            }.keyManagers

    private fun trustManagers(certificate: X509Certificate) =
        KeyStore
            .getInstance("PKCS12")
            .apply {
                load(null, null)
                setCertificateEntry("trusted-synthetic", certificate)
            }.let { store ->
                TrustManagerFactory
                    .getInstance(
                        TrustManagerFactory.getDefaultAlgorithm(),
                    ).apply { init(store) }
                    .trustManagers
            }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}
