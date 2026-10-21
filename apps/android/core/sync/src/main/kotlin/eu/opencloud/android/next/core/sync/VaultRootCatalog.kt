package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.AtomicFile
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/** App-private cache of root descriptors only. No child names, content keys, or account credentials are stored. */
class VaultRootCatalog internal constructor(
    private val root: File,
    private val accountFor: suspend (String) -> AccountEntity?,
    private val endpoints: EndpointPolicy = EndpointPolicy(),
) {
    constructor(context: Context) : this(
        root = File(context.applicationContext.noBackupFilesDir, "vault-root-catalog"),
        accountFor = { accountId ->
            FileBrowserStore(FileBrowserDatabase.create(context.applicationContext)).account(accountId)
        },
    )

    suspend fun folderRoots(
        accountId: String,
        driveId: String,
        parentPath: String,
    ): List<VaultLocation> =
        withContext(Dispatchers.IO) {
            val scope = folderScope(driveId, parentPath)
            read(accountId, scope).filter { location ->
                location.kind == VaultLocationKind.FOLDER_VAULT &&
                    location.driveId == driveId &&
                    parentOf(location.vaultPath) == normalizePath(parentPath)
            }
        }

    suspend fun spaceRoots(accountId: String): List<VaultLocation> =
        withContext(Dispatchers.IO) {
            read(accountId, SPACES_SCOPE).filter { it.kind == VaultLocationKind.SPACE_VAULT }
        }

    /** Replaces one authoritative folder listing so disappeared roots cannot linger in offline discovery. */
    suspend fun replaceFolderRoots(
        accountId: String,
        driveId: String,
        parentPath: String,
        locations: List<VaultLocation>,
    ) = withContext(Dispatchers.IO) {
        val scope = folderScope(driveId, parentPath)
        val account = requireAccount(accountId)
        val server = canonicalServer(account)
        val normalizedParent = normalizePath(parentPath)
        requireDescriptors(locations) { location ->
            location.accountId == accountId &&
                location.kind == VaultLocationKind.FOLDER_VAULT &&
                location.driveId == driveId &&
                parentOf(location.vaultPath) == normalizedParent &&
                location.canonicalServer == server
        }
        write(accountId, server, scope, locations)
    }

    /** Replaces the authoritative online encrypted-Space listing. */
    suspend fun replaceSpaceRoots(
        accountId: String,
        locations: List<VaultLocation>,
    ) = withContext(Dispatchers.IO) {
        val account = requireAccount(accountId)
        val server = canonicalServer(account)
        requireDescriptors(locations) { location ->
            location.accountId == accountId &&
                location.kind == VaultLocationKind.SPACE_VAULT &&
                location.canonicalServer == server
        }
        write(accountId, server, SPACES_SCOPE, locations)
    }

    @Suppress(
        "TooGenericExceptionCaught",
        "ReturnCount",
    ) // Corrupt descriptor data fails closed; early exits bound parsing and reject stale scopes.
    private suspend fun read(
        accountId: String,
        scope: String,
    ): List<VaultLocation> {
        val account = requireAccount(accountId)
        val server = canonicalServer(account)
        val file = scopeFile(accountId, server, scope)
        if (!file.isFile || file.length() > MAX_CATALOG_BYTES) return emptyList()
        return try {
            val value =
                AtomicFile(file).openRead().use { input ->
                    val bytes = readBounded(input)
                    if (bytes.size > MAX_CATALOG_BYTES) return emptyList()
                    JSONObject(String(bytes, StandardCharsets.UTF_8))
                }
            if (!matchesHeader(value, accountId, server, scope)) return emptyList()
            val encoded = value.getJSONArray("roots")
            if (encoded.length() > MAX_ROOTS) return emptyList()
            (0 until encoded.length())
                .mapNotNull { index ->
                    runCatching { decodeVaultRootDescriptor(encoded.getJSONObject(index)) }.getOrNull()
                }.filter { location ->
                    location.accountId == accountId &&
                        location.canonicalServer == server &&
                        location.isVaultRoot
                }.map { it.copy(offlineOnly = true) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    @Suppress(
        "TooGenericExceptionCaught",
        "ThrowsCount",
    ) // AtomicFile must rollback on both checked I/O failures and runtime serialization/write failures.
    private suspend fun write(
        accountId: String,
        server: String,
        scope: String,
        locations: List<VaultLocation>,
    ) {
        val file = scopeFile(accountId, server, scope)
        file.parentFile?.mkdirs()
        val value =
            JSONObject()
                .put("version", VERSION)
                .put("account", accountId)
                .put("server", server)
                .put("scope", scope)
                .put("roots", JSONArray().apply { locations.forEach { put(encodeVaultRootDescriptor(it)) } })
                .toString()
                .toByteArray(StandardCharsets.UTF_8)
        if (value.size > MAX_CATALOG_BYTES) throw OpenCloudException(OpenCloudError.LocalStorage)
        lockFor(file).withLock {
            val atomic = AtomicFile(file)
            val output = atomic.startWrite()
            try {
                output.write(value)
                atomic.finishWrite(output)
            } catch (failure: java.io.IOException) {
                atomic.failWrite(output)
                throw failure
            } catch (failure: RuntimeException) {
                atomic.failWrite(output)
                throw failure
            }
        }
    }

    private suspend fun requireAccount(accountId: String): AccountEntity =
        accountFor(accountId)?.takeIf { it.isActive }
            ?: throw OpenCloudException(OpenCloudError.AuthenticationRequired)

    private fun matchesHeader(
        value: JSONObject,
        accountId: String,
        server: String,
        scope: String,
    ): Boolean =
        value.getInt("version") == VERSION &&
            value.getString("account") == accountId &&
            value.getString("server") == server &&
            value.getString("scope") == scope

    private fun canonicalServer(account: AccountEntity) =
        endpoints.endpoint(account.serverUrl, allowQuery = false).toString()

    private fun requireDescriptors(
        locations: List<VaultLocation>,
        matchesScope: (VaultLocation) -> Boolean,
    ) {
        if (locations.size > MAX_ROOTS || locations.any { !it.isVaultRoot || !matchesScope(it) }) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }

    private fun folderScope(
        driveId: String,
        parentPath: String,
    ) = "folder:${digest(driveId + NUL + normalizePath(parentPath))}"

    private fun scopeFile(
        accountId: String,
        server: String,
        scope: String,
    ) = File(File(root, digest(accountId + NUL + server)), "${digest(scope)}.json")

    private fun normalizePath(path: String) = path.trim('/')

    private fun parentOf(path: String): String = path.trim('/').substringBeforeLast('/', "")

    private fun digest(value: String): String =
        MessageDigest.getInstance("SHA-256").digest(value.toByteArray(StandardCharsets.UTF_8)).joinToString("") {
            "%02x".format(it.toInt() and 0xff)
        }

    private fun readBounded(input: InputStream): ByteArray {
        val buffer = ByteArray(MAX_CATALOG_BYTES + 1)
        var size = 0
        while (size < buffer.size) {
            val count = input.read(buffer, size, buffer.size - size)
            if (count < 0) break
            size += count
        }
        return buffer.copyOf(size)
    }

    private fun lockFor(file: File): Mutex = locks.computeIfAbsent(file.absolutePath) { Mutex() }

    private companion object {
        const val VERSION = 1
        const val SPACES_SCOPE = "spaces"
        const val MAX_ROOTS = 512
        const val MAX_CATALOG_BYTES = 1024 * 1024
        const val NUL = "\u0000"
        val locks = ConcurrentHashMap<String, Mutex>()
    }
}
