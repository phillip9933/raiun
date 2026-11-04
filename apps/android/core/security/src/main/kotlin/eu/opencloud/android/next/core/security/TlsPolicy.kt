package eu.opencloud.android.next.core.security

import android.content.Context
import eu.opencloud.android.next.core.network.EndpointPolicy
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient

/**
 * Applies only explicit, host-scoped SPKI pins. Platform trust and hostname verification remain enabled.
 * This class intentionally has no trust-all trust manager or hostname verifier escape hatch.
 */
class TlsPolicy(
    context: Context,
) {
    private val app = context.applicationContext
    private val preferences = context.getSharedPreferences("tls_trust", Context.MODE_PRIVATE)

    private fun approvedPins(host: String): Set<String> =
        preferences.getStringSet("pins.${host.lowercase()}", emptySet()).orEmpty()

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
        val pins = approvedPins(host)

        // OkHttp accepts pins only through a vararg API; this is the required boundary conversion.
        @Suppress("SpreadOperator")
        val pinned =
            if (pins.isEmpty()) {
                baseClient
            } else {
                baseClient
                    .newBuilder()
                    .certificatePinner(CertificatePinner.Builder().add(host, *pins.toTypedArray()).build())
                    .build()
            }
        val identified = ClientCertificatePolicy(app).applyTo(pinned, canonicalServerUrl)
        val route = ServerConnectionRoute(app)
        return route.applyTo(identified, route.createSnapshot(canonicalServerUrl))
    }
}
