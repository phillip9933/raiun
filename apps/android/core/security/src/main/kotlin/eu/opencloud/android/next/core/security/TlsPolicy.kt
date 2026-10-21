package eu.opencloud.android.next.core.security

import android.content.Context
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import java.net.URI

/**
 * Applies only explicit, host-scoped SPKI pins. Platform trust and hostname verification remain enabled.
 * This class intentionally has no trust-all trust manager or hostname verifier escape hatch.
 */
class TlsPolicy(
    context: Context,
) {
    private val preferences = context.getSharedPreferences("tls_trust", Context.MODE_PRIVATE)

    fun approvedPins(host: String): Set<String> =
        preferences.getStringSet("pins.${host.lowercase()}", emptySet()).orEmpty()

    fun approvePin(
        host: String,
        sha256Pin: String,
    ) {
        require(sha256Pin.startsWith("sha256/")) { "Only SHA-256 SPKI pins are accepted." }
        preferences.edit().putStringSet("pins.${host.lowercase()}", approvedPins(host) + sha256Pin).apply()
    }

    fun removePins(host: String) {
        preferences.edit().remove("pins.${host.lowercase()}").apply()
    }

    @Suppress("ReturnCount")
    fun applyTo(
        baseClient: OkHttpClient,
        serverUrl: String,
    ): OkHttpClient {
        val host = URI(serverUrl).host ?: return baseClient
        val pins = approvedPins(host)
        if (pins.isEmpty()) return baseClient
        // OkHttp accepts pins only through a vararg API; this is the required boundary conversion.
        @Suppress("SpreadOperator")
        return baseClient
            .newBuilder()
            .certificatePinner(CertificatePinner.Builder().add(host, *pins.toTypedArray()).build())
            .build()
    }
}
