package eu.opencloud.android.next.core.security

import android.app.Activity
import android.content.Context
import android.net.Uri
import android.security.KeyChain
import android.security.KeyChainException
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.TransportPolicyException
import okhttp3.ConnectionPool
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Protocol
import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.Socket
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Locale
import javax.net.ssl.KeyManager
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedKeyManager
import javax.net.ssl.X509TrustManager

/** Client identity for a named server and explicitly enumerated TLS origins. No key material is persisted. */
data class ClientCertificateBinding(
    val serverUrl: String,
    val origins: Set<String>,
    val alias: String,
    val certificateSha256: String,
)

sealed class ClientCertificateException : TransportPolicyException(OpenCloudError.ClientCertificateRequired) {
    class Unavailable : ClientCertificateException()

    class Changed : ClientCertificateException()
}

internal data class ClientIdentity(
    val key: PrivateKey,
    val chain: Array<X509Certificate>,
)

internal interface ClientIdentitySource {
    @Throws(IOException::class)
    fun load(alias: String): ClientIdentity?
}

private class KeyChainIdentitySource(
    private val context: Context,
) : ClientIdentitySource {
    @Suppress("ReturnCount")
    override fun load(alias: String): ClientIdentity? {
        try {
            val key = KeyChain.getPrivateKey(context, alias) ?: return null
            val chain = KeyChain.getCertificateChain(context, alias) ?: return null
            if (chain.isEmpty()) return null
            return ClientIdentity(key, chain)
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt()
            throw ClientCertificateException.Unavailable()
        } catch (_: KeyChainException) {
            throw ClientCertificateException.Unavailable()
        } catch (_: SecurityException) {
            throw ClientCertificateException.Unavailable()
        }
    }
}

/**
 * Scoped TLS client-certificate transport for an IdP or reverse proxy. This is not OAuth
 * `tls_client_auth` or RFC 8705 certificate-bound access-token support.
 *
 * Call [save] and [applyTo] on a worker thread. The platform KeyChain grants access to this app,
 * not automatically to the separate browser used for the OIDC authorization page.
 */
class ClientCertificatePolicy internal constructor(
    private val directory: File,
    private val identities: ClientIdentitySource,
) {
    constructor(context: Context) : this(
        File(context.applicationContext.noBackupFilesDir, "client-certificates"),
        KeyChainIdentitySource(context.applicationContext),
    )

    /** Shows Android's certificate chooser. The callback receives null on cancellation. */
    fun chooseAlias(
        activity: Activity,
        serverUrl: String,
        callback: (String?) -> Unit,
    ) {
        val server =
            canonicalServer(serverUrl).toHttpUrlOrNull() ?: throw IllegalArgumentException("Invalid server URL")
        KeyChain.choosePrivateKeyAlias(activity, { callback(it) }, null, null, Uri.parse(server.toString()), null)
    }

    /** Stores only an alias, exact certificate fingerprint, and normalized HTTPS origins. */
    @Suppress("ThrowsCount")
    @Throws(IOException::class)
    fun save(
        serverUrl: String,
        origins: Collection<String>,
        alias: String,
    ): ClientCertificateBinding {
        require(alias.isNotBlank() && alias.length <= 256 && alias.none(Char::isISOControl))
        val canonical = canonicalServer(serverUrl)
        val normalized = origins.map(::canonicalOrigin).toSet()
        require(normalized.isNotEmpty() && normalized.size <= 32)
        val identity = identities.load(alias) ?: throw ClientCertificateException.Unavailable()
        val fingerprint = validateCertificate(identity.chain)
        val binding = ClientCertificateBinding(canonical, normalized, alias, fingerprint)
        val encoded = encode(binding).toByteArray(Charsets.UTF_8)
        require(encoded.size <= MAX_BINDING_BYTES)
        if (!directory.isDirectory &&
            !directory.mkdirs()
        ) {
            throw IOException("Client certificate binding could not be saved")
        }
        val target = fileFor(canonical)
        var temporary: File? = null
        try {
            val pending = File.createTempFile(target.name, ".tmp", directory)
            temporary = pending
            FileOutputStream(pending).use { stream ->
                stream.write(encoded)
                stream.fd.sync()
            }
            Files.move(
                pending.toPath(),
                target.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: IOException) {
            throw ClientCertificateException.Unavailable()
        } finally {
            temporary?.delete()
        }
        return binding
    }

    @Suppress("ComplexCondition", "ThrowsCount")
    fun load(serverUrl: String): ClientCertificateBinding? {
        val canonical = canonicalServer(serverUrl)
        val file = fileFor(canonical)
        if (!file.exists()) return null
        val content = readBounded(file)
        try {
            val data = JSONObject(content)
            val origins = data.getJSONArray("origins")
            val binding =
                ClientCertificateBinding(
                    canonicalServer(data.getString("serverUrl")),
                    (0 until origins.length()).map { canonicalOrigin(origins.getString(it)) }.toSet(),
                    data.getString("alias"),
                    data.getString("certificateSha256"),
                )
            if (binding.serverUrl != canonical ||
                binding.origins.isEmpty() ||
                binding.origins.size > 32 ||
                binding.alias.isBlank() ||
                binding.alias.length > 256 ||
                binding.alias.any(Char::isISOControl) ||
                !binding.certificateSha256.matches(Regex("[0-9a-f]{64}"))
            ) {
                throw ClientCertificateException.Changed()
            }
            return binding
        } catch (_: JSONException) {
            throw ClientCertificateException.Changed()
        } catch (_: IllegalArgumentException) {
            throw ClientCertificateException.Changed()
        }
    }

    fun clear(serverUrl: String) {
        val file = fileFor(canonicalServer(serverUrl))
        if (file.exists() && !file.delete()) throw IOException("Client certificate binding could not be removed")
    }

    /** Creates a dedicated client; only enumerated origins receive this certificate. */
    @Throws(IOException::class)
    fun applyTo(
        baseClient: OkHttpClient,
        serverUrl: String,
    ): OkHttpClient {
        val binding = load(serverUrl) ?: return baseClient
        val trustFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustFactory.init(null as java.security.KeyStore?)
        val trust = trustFactory.trustManagers.filterIsInstance<X509TrustManager>().single()
        val context = SSLContext.getInstance("TLS")
        val peers = ClientCertificatePeerRegistry()
        context.init(
            arrayOf<KeyManager>(
                ScopedKeyManager(binding, identities, peers) { load(binding.serverUrl) },
            ),
            trustFactory.trustManagers,
            null,
        )
        return baseClient
            .newBuilder()
            .sslSocketFactory(ClientCertificateSocketFactory(context.socketFactory, peers), trust)
            // A base client's pool may contain connections negotiated without this identity.
            .connectionPool(ConnectionPool())
            // HTTP/2 may coalesce another SAN origin onto a certificate-authenticated TLS connection.
            .protocols(listOf(Protocol.HTTP_1_1))
            .followRedirects(false)
            .followSslRedirects(false)
            .addInterceptor(
                Interceptor { chain ->
                    val request = chain.request()
                    if (request.url.isHttps && origin(request.url) in binding.origins) {
                        requireCurrent(binding)
                    }
                    chain.proceed(request)
                },
            ).build()
    }

    @Suppress("ThrowsCount")
    internal fun requireCurrent(binding: ClientCertificateBinding): ClientIdentity {
        if (load(binding.serverUrl) != binding) throw ClientCertificateException.Changed()
        val identity = identities.load(binding.alias) ?: throw ClientCertificateException.Unavailable()
        if (validateCertificate(identity.chain) != binding.certificateSha256) throw ClientCertificateException.Changed()
        return identity
    }

    private fun fileFor(serverUrl: String): File =
        File(directory, "${sha256(serverUrl.toByteArray(Charsets.UTF_8))}.json")

    @Suppress("NestedBlockDepth", "ThrowsCount")
    private fun readBounded(file: File): String {
        if (file.length() > MAX_BINDING_BYTES) throw ClientCertificateException.Changed()
        val output = ByteArrayOutputStream()
        try {
            FileInputStream(file).use { input ->
                val buffer = ByteArray(1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (output.size() + count > MAX_BINDING_BYTES) throw ClientCertificateException.Changed()
                    output.write(buffer, 0, count)
                }
            }
        } catch (_: IOException) {
            throw ClientCertificateException.Changed()
        }
        return output.toString(Charsets.UTF_8.name())
    }

    private fun encode(binding: ClientCertificateBinding): String =
        JSONObject()
            .put("serverUrl", binding.serverUrl)
            .put("origins", JSONArray(binding.origins.sorted()))
            .put("alias", binding.alias)
            .put("certificateSha256", binding.certificateSha256)
            .toString()

    companion object {
        private const val MAX_BINDING_BYTES = 16 * 1024

        fun normalizeServerUrl(value: String): String = canonicalServer(value)

        fun normalizeOrigin(value: String): String = canonicalOrigin(value)
    }
}

internal class ScopedKeyManager(
    private val binding: ClientCertificateBinding,
    private val identities: ClientIdentitySource,
    private val peers: ClientCertificatePeerRegistry? = null,
    private val currentBinding: () -> ClientCertificateBinding?,
) : X509ExtendedKeyManager() {
    @Suppress("ReturnCount")
    override fun chooseClientAlias(
        keyTypes: Array<out String>?,
        issuers: Array<out java.security.Principal>?,
        socket: Socket?,
    ): String? {
        val peer = socket?.let { peers?.peer(it) }
        if (peer != null) return select(peer.host, peer.port, keyTypes)
        val session = (socket as? SSLSocket)?.handshakeSession ?: return null
        return select(session.peerHost, session.peerPort, keyTypes)
    }

    override fun chooseEngineClientAlias(
        keyTypes: Array<out String>?,
        issuers: Array<out java.security.Principal>?,
        engine: SSLEngine?,
    ): String? {
        val session = engine?.handshakeSession ?: return null
        return select(session.peerHost, session.peerPort, keyTypes)
    }

    @Suppress("ReturnCount")
    internal fun select(
        host: String?,
        port: Int,
        keyTypes: Array<out String>?,
    ): String? {
        if (host.isNullOrBlank() || port !in 1..65535 || currentBinding() != binding) return null
        val origin =
            runCatching {
                okhttp3.HttpUrl
                    .Builder()
                    .scheme("https")
                    .host(host)
                    .port(port)
                    .build()
                    .let(::origin)
            }.getOrNull() ?: return null
        if (origin !in binding.origins) return null
        val identity = identities.load(binding.alias) ?: throw ClientCertificateException.Unavailable()
        if (validateCertificate(identity.chain) != binding.certificateSha256) throw ClientCertificateException.Changed()
        if (keyTypes != null && keyTypes.none { it.equals(identity.key.algorithm, ignoreCase = true) }) return null
        return binding.alias
    }

    override fun getPrivateKey(alias: String?): PrivateKey? =
        if (alias ==
            binding.alias
        ) {
            currentIdentity().key
        } else {
            null
        }

    override fun getCertificateChain(alias: String?): Array<X509Certificate>? =
        if (alias ==
            binding.alias
        ) {
            currentIdentity().chain
        } else {
            null
        }

    @Suppress("ThrowsCount")
    private fun currentIdentity(): ClientIdentity {
        if (currentBinding() != binding) throw ClientCertificateException.Changed()
        val identity = identities.load(binding.alias) ?: throw ClientCertificateException.Unavailable()
        if (validateCertificate(identity.chain) != binding.certificateSha256) throw ClientCertificateException.Changed()
        return identity
    }

    override fun getClientAliases(
        keyType: String?,
        issuers: Array<out java.security.Principal>?,
    ): Array<String>? = null

    override fun chooseServerAlias(
        keyType: String?,
        issuers: Array<out java.security.Principal>?,
        socket: Socket?,
    ): String? = null

    override fun getServerAliases(
        keyType: String?,
        issuers: Array<out java.security.Principal>?,
    ): Array<String>? = null

    override fun chooseEngineServerAlias(
        keyType: String?,
        issuers: Array<out java.security.Principal>?,
        engine: SSLEngine?,
    ): String? = null
}

private fun canonicalServer(value: String): String {
    require(value.length <= 2048)
    val url = value.toHttpUrlOrNull() ?: throw IllegalArgumentException("Invalid server URL")
    require(
        url.isHttps && url.username.isEmpty() && url.password.isEmpty() && url.query == null && url.fragment == null,
    )
    return url.toString().trimEnd('/')
}

private fun canonicalOrigin(value: String): String {
    require(value.length <= 2048)
    val url = value.toHttpUrlOrNull() ?: throw IllegalArgumentException("Invalid HTTPS origin")
    require(
        url.isHttps && url.username.isEmpty() && url.password.isEmpty() && url.query == null && url.fragment == null,
    )
    require(url.encodedPath == "/") { "An origin cannot include a path" }
    return origin(url)
}

private fun origin(url: HttpUrl): String =
    url
        .newBuilder()
        .encodedPath("/")
        .query(null)
        .fragment(null)
        .build()
        .toString()
        .trimEnd('/')

@Suppress("ThrowsCount")
private fun validateCertificate(chain: Array<X509Certificate>): String {
    val leaf = chain.firstOrNull() ?: throw ClientCertificateException.Unavailable()
    try {
        leaf.checkValidity()
        val keyUsage = leaf.keyUsage
        if (keyUsage != null && (keyUsage.isEmpty() || !keyUsage[0])) {
            throw ClientCertificateException.Unavailable()
        }
        val extendedUsage = leaf.extendedKeyUsage
        if (extendedUsage != null &&
            CLIENT_AUTH_OID !in extendedUsage &&
            ANY_EXTENDED_KEY_USAGE_OID !in extendedUsage
        ) {
            throw ClientCertificateException.Unavailable()
        }
    } catch (_: java.security.cert.CertificateExpiredException) {
        throw ClientCertificateException.Unavailable()
    } catch (_: java.security.cert.CertificateNotYetValidException) {
        throw ClientCertificateException.Unavailable()
    } catch (_: java.security.cert.CertificateParsingException) {
        throw ClientCertificateException.Unavailable()
    }
    return sha256(leaf.encoded)
}

private fun sha256(bytes: ByteArray): String =
    MessageDigest
        .getInstance("SHA-256")
        .digest(bytes)
        .joinToString("") { "%02x".format(Locale.ROOT, it.toInt() and 0xff) }

private const val CLIENT_AUTH_OID = "1.3.6.1.5.5.7.3.2"
private const val ANY_EXTENDED_KEY_USAGE_OID = "2.5.29.37.0"
