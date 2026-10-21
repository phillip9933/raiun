package eu.opencloud.android.next.core.network

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okio.Buffer

enum class EmbeddedWebAppMode(
    val wireValue: String,
) {
    VIEW("view"),
    WRITE("write"),
}

data class EmbeddedWebAppRequest(
    val fileId: String,
    val app: ServerWebApp,
    val mode: EmbeddedWebAppMode = EmbeddedWebAppMode.VIEW,
)

/** Sensitive, memory-only handoff. Deliberately not a data class or serializable/saveable state. */
class EmbeddedWebAppSession internal constructor(
    val url: String,
    val method: String,
    parameters: Map<String, String>,
) {
    private val parameters = parameters.toMap()

    /** Exact application/x-www-form-urlencoded bytes, never HTML/JavaScript interpolation. */
    fun postBody(): ByteArray? {
        if (method != "POST") return null
        val body = FormBody.Builder().apply { parameters.forEach { (name, value) -> add(name, value) } }.build()
        return Buffer().also { body.writeTo(it) }.readByteArray()
    }

    override fun toString(): String = "EmbeddedWebAppSession(redacted)"
}

@Serializable
internal class EmbeddedWebAppResponse(
    @SerialName("app_url") private val appUrl: String,
    private val method: String,
    @SerialName("form_parameters") private val parameters: Map<String, String>? = null,
) {
    fun session(endpoints: EndpointPolicy): EmbeddedWebAppSession {
        val form = parameters.orEmpty()
        if (method !in setOf("GET", "POST") || (method == "GET" && form.isNotEmpty())) invalid()
        if (form.size > 64 || form.any { !validParameter(it.key, it.value) }) invalid()
        if (form.values.sumOf { it.length.toLong() } > 256 * 1024) invalid()
        if (appUrl.length > 8192 || appUrl.any { it.isISOControl() }) trust()
        val parsed = appUrl.toHttpUrlOrNull() ?: trust()
        endpoints.endpoint(
            parsed
                .newBuilder()
                .fragment(null)
                .build()
                .toString(),
        )
        return EmbeddedWebAppSession(parsed.toString(), method, form)
    }

    private fun validParameter(
        name: String,
        value: String,
    ): Boolean = name.isNotBlank() && name.length <= 128 && name.none { it.isISOControl() } && value.length <= 64 * 1024

    private fun invalid(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

    private fun trust(): Nothing = throw OpenCloudException(OpenCloudError.Trust)

    override fun toString(): String = "EmbeddedWebAppResponse(redacted)"
}
