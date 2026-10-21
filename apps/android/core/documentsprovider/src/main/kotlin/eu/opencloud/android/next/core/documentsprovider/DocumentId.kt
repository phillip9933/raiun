package eu.opencloud.android.next.core.documentsprovider

import java.io.FileNotFoundException
import java.nio.charset.StandardCharsets
import java.util.Base64

internal sealed interface DocumentId {
    data class Account(
        val accountId: String,
    ) : DocumentId

    data class Space(
        val accountId: String,
        val spaceId: String,
    ) : DocumentId

    data class Resource(
        val accountId: String,
        val spaceId: String,
        val resourceId: String,
    ) : DocumentId

    fun encode(): String {
        val raw =
            when (this) {
                is Account -> listOf(VERSION, "account", accountId)
                is Space -> listOf(VERSION, "space", accountId, spaceId)
                is Resource -> listOf(VERSION, "resource", accountId, spaceId, resourceId)
            }.joinToString("\u0000")
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.toByteArray(StandardCharsets.UTF_8))
    }

    companion object {
        fun decode(encoded: String): DocumentId {
            if (encoded.length !in 1..4096) invalidDocumentId()
            val values =
                runCatching {
                    String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8).split("\u0000")
                }.getOrElse { invalidDocumentId() }
            if (values.firstOrNull() != VERSION) invalidDocumentId("Unsupported document ID.")
            val count =
                when (values.getOrNull(1)) {
                    "account" -> 3
                    "space" -> 4
                    "resource" -> 5
                    else -> invalidDocumentId()
                }
            if (values.size != count) invalidDocumentId()
            return when (values.getOrNull(1)) {
                "account" -> Account(values.required(2))
                "space" -> Space(values.required(2), values.required(3))
                "resource" -> Resource(values.required(2), values.required(3), values.required(4))
                else -> invalidDocumentId()
            }
        }

        private const val VERSION = "v1"
    }
}

private fun List<String>.required(index: Int): String =
    getOrNull(index)?.takeIf(String::isNotBlank) ?: invalidDocumentId()

private fun invalidDocumentId(message: String = "Invalid document ID."): Nothing = throw FileNotFoundException(message)
