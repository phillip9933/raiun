package eu.opencloud.android.next.core.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.InetAddress
import java.net.Socket
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Provider
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

/** Uses disposable synthetic PKCS12 identities in test resources only; no production credentials. */
class ClientCertificateTlsTest {
    private val password = "synthetic-test-only".toCharArray()

    private enum class OriginScope { MATCH, WRONG_HOST, WRONG_PORT }

    @Test fun `TLS sends selected certificate only to configured origin`() {
        withSunEcBeforeConscrypt {
            runHandshakes()
        }
    }

    private fun runHandshakes() {
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
            hostTlsContext().apply {
                init(keyManagers(serverStore), trustManagers(clientCertificate), null)
            }

        handshake(serverContext, serverCertificate, source, clientCertificate, OriginScope.MATCH)
        handshake(serverContext, serverCertificate, source, clientCertificate, OriginScope.WRONG_HOST)
        handshake(serverContext, serverCertificate, source, clientCertificate, OriginScope.WRONG_PORT)
    }

    @Suppress("NestedBlockDepth")
    private fun handshake(
        serverContext: SSLContext,
        serverCertificate: X509Certificate,
        source: ClientIdentitySource,
        clientCertificate: X509Certificate,
        scope: OriginScope,
    ) {
        val server =
            serverContext.serverSocketFactory.createServerSocket(
                0,
                1,
                InetAddress.getByName("127.0.0.1"),
            ) as SSLServerSocket
        server.needClientAuth = true
        server.enabledProtocols = arrayOf("TLSv1.3")
        server.soTimeout = 5_000
        val port = server.localPort
        val origin =
            when (scope) {
                OriginScope.MATCH -> "https://localhost:$port"
                OriginScope.WRONG_HOST -> "https://different.example.test:$port"
                OriginScope.WRONG_PORT -> "https://localhost:${port + 1}"
            }
        val binding =
            ClientCertificateBinding(
                "https://cloud.example.test",
                setOf(origin),
                "client",
                sha256(clientCertificate.encoded),
            )
        val clientProvider = conscryptProvider()
        val peers = ClientCertificatePeerRegistry()
        val clientContext =
            SSLContext.getInstance("TLS", clientProvider).apply {
                init(
                    arrayOf(ScopedKeyManager(binding, source, peers) { binding }),
                    trustManagers(serverCertificate, clientProvider),
                    null,
                )
            }
        val executor = Executors.newSingleThreadExecutor()
        try {
            val peerCertificate =
                executor.submit<X509Certificate?> {
                    server.use { listener ->
                        (listener.accept() as SSLSocket).use { socket ->
                            socket.soTimeout = 5_000
                            socket.enabledProtocols = arrayOf("TLSv1.3")
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
                            if (scope ==
                                OriginScope.MATCH
                            ) {
                                serverHandshake.getOrThrow()
                            } else {
                                serverHandshake.getOrNull()
                            }
                        }
                    }
                }
            val clientHandshake =
                Socket("127.0.0.1", port).use { transport ->
                    val tlsSocket =
                        ClientCertificateSocketFactory(clientContext.socketFactory, peers).createSocket(
                            transport,
                            "localhost",
                            port,
                            true,
                        ) as SSLSocket
                    tlsSocket.use { socket ->
                        assertEquals(ClientCertificatePeer("localhost", port), peers.peer(socket))
                        socket.soTimeout = 5_000
                        socket.enabledProtocols = arrayOf("TLSv1.3")
                        val parameters = socket.sslParameters
                        parameters.endpointIdentificationAlgorithm = "HTTPS"
                        socket.sslParameters = parameters
                        runCatching {
                            socket.startHandshake()
                            socket.inputStream.read().also { if (it == 7) socket.outputStream.write(8) }
                        }
                    }
                }
            val peer = peerCertificate.get(10, TimeUnit.SECONDS)
            if (scope == OriginScope.MATCH) {
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
            requireNotNull(
                ClientCertificateTlsTest::class.java.classLoader?.getResourceAsStream(name),
            ).use { encoded ->
                Base64.getMimeDecoder().wrap(encoded).use { decoded ->
                    load(decoded, password)
                }
            }
        }

    private fun keyManagers(store: KeyStore) =
        KeyManagerFactory
            .getInstance(KeyManagerFactory.getDefaultAlgorithm(), "SunJSSE")
            .apply {
                init(store, password)
            }.keyManagers

    private fun trustManagers(
        certificate: X509Certificate,
        provider: Provider? = null,
    ) = KeyStore
        .getInstance("PKCS12")
        .apply {
            load(null, null)
            setCertificateEntry("trusted-synthetic", certificate)
        }.let { store ->
            val factory =
                if (provider == null) {
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(), "SunJSSE")
                } else {
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm(), provider)
                }
            factory
                .apply { init(store) }
                .trustManagers
        }

    private fun sha256(bytes: ByteArray): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private fun hostTlsContext(): SSLContext = SSLContext.getInstance("TLS", "SunJSSE")

    private fun conscryptProvider(): Provider =
        Security.getProviders().firstOrNull {
            it.javaClass.name.startsWith("org.conscrypt.") && it.getService("SSLContext", "TLS") != null
        } ?: Class.forName("org.conscrypt.Conscrypt").getMethod("newProvider").invoke(null) as Provider

    private inline fun <T> withSunEcBeforeConscrypt(block: () -> T): T {
        val sunEc = requireNotNull(Security.getProvider("SunEC"))
        val originalPosition = Security.getProviders().indexOf(sunEc) + 1
        check(originalPosition > 0)
        if (originalPosition > 1) {
            Security.removeProvider(sunEc.name)
            check(Security.insertProviderAt(sunEc, 1) == 1)
        }
        return try {
            block()
        } finally {
            if (originalPosition > 1) {
                Security.removeProvider(sunEc.name)
                check(Security.insertProviderAt(sunEc, originalPosition) == originalPosition)
            }
        }
    }
}
