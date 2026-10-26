package eu.opencloud.android.next.core.security

import java.net.InetAddress
import java.net.Socket
import java.util.Collections
import java.util.WeakHashMap
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** The exact host supplied to SSLSocketFactory by the HTTP client, before DNS resolution. */
internal data class ClientCertificatePeer(
    val host: String,
    val port: Int,
)

internal class ClientCertificatePeerRegistry {
    private val peers = Collections.synchronizedMap(WeakHashMap<Socket, ClientCertificatePeer>())

    fun record(
        socket: Socket,
        host: String,
        port: Int,
    ): Socket {
        if (socket is SSLSocket && host.isNotBlank() && port in 1..65535) {
            peers[socket] = ClientCertificatePeer(host, port)
        }
        return socket
    }

    fun peer(socket: Socket): ClientCertificatePeer? = peers[socket]
}

/** API 26 can invoke the key manager before SSLSocket.handshakeSession exists. */
internal class ClientCertificateSocketFactory(
    private val delegate: SSLSocketFactory,
    private val peers: ClientCertificatePeerRegistry,
) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites

    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createSocket(
        socket: Socket,
        host: String,
        port: Int,
        autoClose: Boolean,
    ): Socket = peers.record(delegate.createSocket(socket, host, port, autoClose), host, port)

    override fun createSocket(
        host: String,
        port: Int,
    ): Socket = peers.record(delegate.createSocket(host, port), host, port)

    override fun createSocket(
        host: String,
        port: Int,
        localHost: InetAddress,
        localPort: Int,
    ): Socket = peers.record(delegate.createSocket(host, port, localHost, localPort), host, port)

    override fun createSocket(
        host: InetAddress,
        port: Int,
    ): Socket = peers.record(delegate.createSocket(host, port), host.hostAddress.orEmpty(), port)

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress,
        localPort: Int,
    ): Socket =
        peers.record(delegate.createSocket(address, port, localAddress, localPort), address.hostAddress.orEmpty(), port)
}
