package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import java.io.ByteArrayOutputStream
import java.io.File

internal class VaultAccess(
    val account: AccountEntity,
    val canonicalServer: String,
    authorizationValue: String,
    httpClient: OkHttpClient?,
    val permit: () -> Boolean,
    private val currentAccount: suspend () -> AccountEntity?,
) {
    var authorization: String = authorizationValue
        internal set
    private var configuredHttp = httpClient
    var http: OkHttpClient
        get() = checkNotNull(configuredHttp) { "Vault transport is not configured" }
        internal set(value) {
            configuredHttp = value
        }

    suspend fun requireCurrent() {
        currentCoroutineContext().ensureActive()
        if (!permit()) throw OpenCloudException(OpenCloudError.AccessDenied)
        if (currentAccount() != account) throw OpenCloudException(OpenCloudError.PreconditionFailed)
        currentCoroutineContext().ensureActive()
    }
}

internal class WipingByteArrayOutputStream(
    initialSize: Int,
) : ByteArrayOutputStream(initialSize) {
    fun wipe() {
        buf.fill(0)
        reset()
    }

    fun copyBytes(): ByteArray = toByteArray()
}

internal fun VaultDavEntry.toFolder(
    path: String,
    isVaultRoot: Boolean,
    displayName: String = rawName,
    leaseId: String? = null,
) = VaultFolder(
    id = id,
    name = displayName,
    rawName = rawName,
    path = path,
    encryptedPath = relativePath,
    isFolder = isFolder,
    size = size,
    strongETag = strongETag,
    isVaultRoot = isVaultRoot,
    leaseId = leaseId,
)

internal fun joinDavPaths(
    first: String,
    second: String,
): String = listOf(first, second).filter(String::isNotEmpty).joinToString("/")

internal fun validateVaultExcludedPath(path: String?): String? =
    path?.let {
        if (it.isEmpty()) throw OpenCloudException(OpenCloudError.Unsupported)
        validatePlainPath(it)
    }

internal fun vaultChildVisible(
    name: String,
    path: String,
    showHidden: Boolean,
    excludedPath: String?,
): Boolean {
    val hidden = !showHidden && name.startsWith('.')
    val excluded = excludedPath != null && (path == excludedPath || path.startsWith("$excludedPath/"))
    return !hidden && !excluded
}

internal fun validatePlainPath(path: String): String {
    if (path.isEmpty()) return path
    val segments = path.split('/')
    if (path.startsWith('/') ||
        path.endsWith('/') ||
        segments.any(::isInvalidPlainSegment)
    ) {
        throw OpenCloudException(OpenCloudError.Unsupported)
    }
    return path
}

internal fun validateSingleName(name: String): String {
    if (name.isEmpty() || name.length > 255) throw OpenCloudException(OpenCloudError.Unsupported)
    if (hasInvalidNameStructure(name)) throw OpenCloudException(OpenCloudError.Unsupported)
    return name
}

private fun hasInvalidNameStructure(name: String): Boolean {
    val traversal = name == "." || name == ".."
    val separator = name.contains('/') || name.contains('\\')
    return traversal || separator || name.any(Char::isISOControl)
}

internal fun vaultFolderName(name: String): String {
    val safeName = validateSingleName(name.removeSuffix(".vault"))
    return "$safeName.vault"
}

/** Private ciphertext-only staging for SAF providers that omit a source length. */
internal object VaultCiphertextSpools {
    private val active = mutableSetOf<String>()

    @Suppress("ComplexCondition") // Only abandoned ciphertext stages with this exact naming scheme are deleted.
    @Synchronized
    fun removeStale(directory: File) {
        if (!directory.exists()) return
        if (!directory.isDirectory) throw OpenCloudException(OpenCloudError.Unsupported)
        directory.listFiles()?.forEach { file ->
            if (file.isFile &&
                file.name.startsWith("vault-") &&
                file.name.endsWith(".ciphertext") &&
                file.path !in active
            ) {
                file.delete()
            }
        }
    }

    @Synchronized fun create(directory: File): File {
        if (!directory.isDirectory && !directory.mkdirs()) throw OpenCloudException(OpenCloudError.Unsupported)
        val file = File.createTempFile("vault-", ".ciphertext", directory)
        active += file.path
        return file
    }

    @Synchronized fun delete(file: File) {
        file.delete()
        active -= file.path
    }
}

private fun isInvalidPlainSegment(segment: String): Boolean =
    segment in setOf("", ".", "..") || segment.any(Char::isISOControl) || segment.contains('\\')

internal fun resolveEntryHref(
    root: String,
    relativePath: String,
): String =
    root
        .toHttpUrl()
        .newBuilder()
        .apply { relativePath.split('/').forEach(::addPathSegment) }
        .build()
        .toString()
