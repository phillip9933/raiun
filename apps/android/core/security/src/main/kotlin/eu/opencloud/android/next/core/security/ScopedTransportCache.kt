package eu.opencloud.android.next.core.security

import okhttp3.CertificatePinner
import okhttp3.ConnectionPool
import okhttp3.OkHttpClient
import java.util.WeakHashMap
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLContext

/** Identity equality is intentional: independently configured trust or routing must never share a pool. */
internal class TransportIdentity(
    private val value: Any?,
) {
    override fun equals(other: Any?): Boolean = other is TransportIdentity && value === other.value

    override fun hashCode(): Int = System.identityHashCode(value)
}

internal data class TransportBaseKey(
    val pool: TransportIdentity,
    val ssl: TransportIdentity,
    val trust: TransportIdentity,
    val verifier: TransportIdentity,
    // OkHttp recreates equal immutable pinners when applying the same TLS chain cleaner.
    val pinner: CertificatePinner,
    val dns: TransportIdentity,
    val sockets: TransportIdentity,
    val proxy: Any?,
    val proxySelector: TransportIdentity,
    val proxyAuthenticator: TransportIdentity,
    val protocols: List<okhttp3.Protocol>,
    val connectionSpecs: List<okhttp3.ConnectionSpec>,
)

internal fun OkHttpClient.transportKey() =
    TransportBaseKey(
        TransportIdentity(connectionPool),
        TransportIdentity(sslSocketFactory),
        TransportIdentity(x509TrustManager),
        TransportIdentity(hostnameVerifier),
        certificatePinner,
        TransportIdentity(dns),
        TransportIdentity(socketFactory),
        proxy,
        TransportIdentity(proxySelector),
        TransportIdentity(proxyAuthenticator),
        protocols.toList(),
        connectionSpecs.toList(),
    )

internal interface ScopedTransportParts {
    val pool: ConnectionPool

    fun retire() = pool.evictAll()
}

/** Only transport parts are retained. No dispatcher, request credentials, client or private key is cached. */
internal object ScopedTransportCache {
    internal const val MAX_ENTRIES = 32
    private val entries = LinkedHashMap<Any, ScopedTransportParts>(16, 0.75f, true)

    // Weak keys retain descriptors only while a cache entry or a caller still owns its guard.
    private val guards = WeakHashMap<TransportGuard, GuardDescriptor>()

    fun guard(
        scope: Any,
        state: Any?,
    ): TransportGuard = guardDeferred(scope, state).also { it.retire() }.guard

    @Synchronized
    fun guardDeferred(
        scope: Any,
        state: Any?,
    ): TransportAdmission {
        val matching = liveGuards().filter { it.second.scope == scope }
        val existing = matching.firstOrNull { it.first.isCurrent() && it.second.state == state }?.first
        if (existing != null) return TransportAdmission(existing, emptyList())
        matching.forEach { it.first.revoke() }
        val retired = removeRevoked()
        val guard = TransportGuard().also { guards[it] = GuardDescriptor(scope, state) }
        return TransportAdmission(guard, retired)
    }

    fun revoke(scope: Any) = revokeDeferred(scope).forEach(ScopedTransportParts::retire)

    @Synchronized
    fun revokeDeferred(scope: Any): List<ScopedTransportParts> {
        liveGuards().filter { it.second.scope == scope }.forEach { it.first.revoke() }
        return removeRevoked()
    }

    fun revokeRouteNetwork(network: Any) = revokeMatching { (it.state as? RouteState)?.networkIdentity == network }

    private fun revokeMatching(matches: (GuardDescriptor) -> Boolean) {
        val retired =
            synchronized(this) {
                liveGuards().filter { matches(it.second) }.forEach { it.first.revoke() }
                removeRevoked()
            }
        retired.forEach(ScopedTransportParts::retire)
    }

    private fun liveGuards(): List<Pair<TransportGuard, GuardDescriptor>> =
        guards.entries.mapNotNull { entry -> entry.key?.let { it to entry.value } }

    private fun removeRevoked(): List<ScopedTransportParts> {
        val retired = mutableListOf<ScopedTransportParts>()
        val iterator = entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.key is ScopedPartsKey &&
                (
                    !(entry.key as ScopedPartsKey).guard.isCurrent() ||
                        (entry.key as ScopedPartsKey).isolation?.isCurrent() == false
                )
            ) {
                retired += entry.value
                iterator.remove()
            }
        }
        return retired
    }

    fun <T : ScopedTransportParts> getOrCreate(
        key: ScopedPartsKey,
        create: () -> T,
    ): T {
        synchronized(this) {
            @Suppress("UNCHECKED_CAST") // Each private key type belongs to exactly one parts type.
            val existing = entries[key] as T?
            if (existing != null) return existing
        }
        val candidate = create()
        val retired = mutableListOf<ScopedTransportParts>()
        val result =
            synchronized(this) {
                @Suppress("UNCHECKED_CAST")
                val existing = entries[key] as T?
                if (existing != null) {
                    retired += candidate
                    existing
                } else {
                    if (key.guard.isCurrent() && key.isolation?.isCurrent() != false) {
                        entries[key] = candidate
                        if (entries.size > MAX_ENTRIES) {
                            val oldest = entries.entries.iterator()
                            retired += oldest.next().value
                            oldest.remove()
                        }
                    } else {
                        retired += candidate
                    }
                    candidate
                }
            }
        retired.forEach(ScopedTransportParts::retire)
        return result
    }

    /** Pin changes may retire idle resources conservatively; caller pin guards retain revocation authority. */
    fun invalidateAll() {
        val retired =
            synchronized(this) {
                entries.values.toList().also { entries.clear() }
            }
        retired.forEach(ScopedTransportParts::retire)
    }

    @Synchronized
    internal fun size(): Int = entries.size
}

internal fun SSLContext.retireSessions() {
    val sessions = clientSessionContext
    val ids = sessions.ids
    while (ids.hasMoreElements()) sessions.getSession(ids.nextElement())?.invalidate()
}

internal class TransportGuard {
    private val current = AtomicBoolean(true)

    fun isCurrent(): Boolean = current.get()

    fun revoke() = current.set(false)
}

private data class GuardDescriptor(
    val scope: Any,
    val state: Any?,
)

internal data class ScopedPartsKey(
    val guard: TransportGuard,
    val base: TransportBaseKey,
    val isolation: TransportGuard? = null,
)

internal data class TransportAdmission(
    val guard: TransportGuard,
    private val retired: List<ScopedTransportParts>,
) {
    fun retire() = retired.forEach(ScopedTransportParts::retire)
}
