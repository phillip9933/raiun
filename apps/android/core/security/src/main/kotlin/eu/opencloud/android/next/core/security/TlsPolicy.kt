package eu.opencloud.android.next.core.security

import android.content.Context
import eu.opencloud.android.next.core.network.EndpointPolicy
import okhttp3.OkHttpClient

/**
 * Applies only explicit, host-scoped SPKI pins. Platform trust and hostname verification remain enabled.
 * This class intentionally has no trust-all trust manager or hostname verifier escape hatch.
 */
class TlsPolicy internal constructor(
    context: Context,
    private val certificatePolicy: ClientCertificatePolicy,
) {
    constructor(context: Context) : this(context, ClientCertificatePolicy(context))

    private val app = context.applicationContext
    private val pinStore = LegacyCertificatePinStore(app)

    @Suppress("ReturnCount")
    fun applyTo(
        baseClient: OkHttpClient,
        serverUrl: String,
    ): OkHttpClient {
        // Auth creates an unconfigured repository before a server has been selected.
        if (serverUrl.isEmpty()) return baseClient
        // Use the request client's parser: java.net.URI rejects some OkHttp hosts (for
        // example underscores), which must never bypass pin, identity or route policy.
        val endpoint = EndpointPolicy().endpoint(serverUrl, allowQuery = false)
        val host = endpoint.host
        val canonicalServerUrl = endpoint.toString()
        val pins = pinStore.pinsFor(host)

        val route = ServerConnectionRoute(app)
        val snapshot = route.createSnapshot(canonicalServerUrl)
        val identified = certificatePolicy.applyTo(baseClient, canonicalServerUrl, snapshot.transportGuard)
        val routed = route.applyTo(identified, snapshot)
        return pinStore.applyTo(routed, host, pins)
    }
}
