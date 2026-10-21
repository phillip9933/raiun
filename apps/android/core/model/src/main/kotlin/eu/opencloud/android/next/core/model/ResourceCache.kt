package eu.opencloud.android.next.core.model

import java.io.File
import java.util.Base64

fun cacheIdentity(value: String): String =
    "id-" + Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray())

fun resourceCacheDirectory(
    filesDir: File,
    accountId: String,
    spaceId: String,
): File = File(filesDir, "resources-v2/${cacheIdentity(accountId)}/${cacheIdentity(spaceId)}")

fun validatedCachedFile(
    directory: File,
    path: String?,
    size: Long,
): File? {
    val file = path?.let(::File)?.canonicalFile ?: return null
    return file.takeIf { it.parentFile == directory.canonicalFile && it.isFile && it.length() == size }
}
