package eu.opencloud.android.next.core.network

import org.w3c.dom.Element

internal fun Element.isEncryptedVault(): Boolean =
    successfulVaultProperty("ocrclone", "integrity-id")?.isNotBlank() == true ||
        successfulVaultProperty("DAV:", "getcontenttype") == VAULT_CONTENT_TYPE

internal fun Element.successfulVaultProperty(
    namespace: String,
    name: String,
): String? {
    val properties = getElementsByTagNameNS(namespace, name)
    return (0 until properties.length).firstNotNullOfOrNull { index ->
        val property = properties.item(index)
        val propstat = property.parentNode?.parentNode as? Element
        val status =
            propstat
                ?.getElementsByTagNameNS("DAV:", "status")
                ?.item(0)
                ?.textContent
                .orEmpty()
        if (status.split(' ').getOrNull(1) == "200") property.textContent else null
    }
}

internal fun Element.confirmsPlainCollection(): Boolean {
    val contentType = successfulVaultProperty("DAV:", "getcontenttype")
    val integrityId = successfulVaultProperty("ocrclone", "integrity-id")
    val hasPlainContentType = !contentType.isNullOrBlank() && contentType != VAULT_CONTENT_TYPE
    val hasEmptyIntegrityId = integrityId != null && integrityId.isBlank()
    return hasPlainContentType && hasEmptyIntegrityId
}

internal fun isVaultPath(path: String): Boolean = path.split('/').any { it.endsWith(".vault", ignoreCase = true) }

internal const val VAULT_CONTENT_TYPE = "application/vnd.opencloud.vault"

internal fun Element.excludesVaultPath(path: String): Boolean = isEncryptedVault() || isVaultPath(path)
