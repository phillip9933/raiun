package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.CoroutineContext

/** Read-only snapshot bound to identity, account/lock permits and revocation generations at open. */
@Suppress("LongParameterList")
class VaultOfflineSession internal constructor(
    val identity: VaultIdentity,
    val location: VaultLocation,
    private val directory: File,
    private val manifest: OfflineManifest,
    private val cipher: VaultCipherEngine,
    private val keyMaterial: ByteArray,
    private val permit: () -> Boolean,
    private val accountAtOpen: AccountEntity,
    private val accountFor: suspend (String) -> AccountEntity?,
    private val endpoints: EndpointPolicy,
    private val accountGeneration: Long,
    private val identityGeneration: Long,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val exported = AtomicBoolean(false)
    private val issuedEntries = ConcurrentHashMap<String, VaultFolder>()

    suspend fun list(path: String = ""): List<VaultFolder> =
        withContext(Dispatchers.IO) {
            requireAccess()
            val encoded = cipher.encryptPath(path)
            val parent = joinEncrypted(location.vaultPath, encoded)
            val children =
                manifest.entries.values
                    .asSequence()
                    .filter { it.encryptedPath.substringBeforeLast('/', "") == parent }
                    .filter { it.isFolder || it.blobId != null }
                    .map { cached ->
                        val plainName = cipher.decryptName(cached.rawName)
                        val plainPath = if (path.isEmpty()) plainName else "$path/$plainName"
                        VaultFolder(
                            id = cached.id.ifBlank { cached.encryptedPath },
                            name = plainName,
                            rawName = cached.rawName,
                            path = plainPath,
                            encryptedPath = cached.encryptedPath,
                            isFolder = cached.isFolder,
                            size = cached.size,
                            strongETag = cached.etag,
                            leaseId = UUID.randomUUID().toString(),
                        )
                    }.sortedWith(compareBy<VaultFolder> { !it.isFolder }.thenBy { it.name.lowercase() })
                    .toList()
            requireAccess()
            issuedEntries.clear()
            children.forEach { issuedEntries[it.leaseId!!] = it }
            children
        }

    /** The caller owns the sink and must remove a newly created destination if any block fails. */
    suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long = Long.MAX_VALUE,
    ): Long =
        withContext(Dispatchers.IO) {
            requireAccess()
            if (maxPlaintextBytes < 0 || entry.isFolder || issuedEntries[entry.leaseId] != entry) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            val cached =
                manifest.entries[entry.encryptedPath]
                    ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val blobId = cached.blobId ?: throw OpenCloudException(OpenCloudError.PreconditionFailed)
            val blob = File(File(directory, "blobs"), blobId)
            val context = currentCoroutineContext()
            if (!blob.isFile ||
                blob.length() != cached.size ||
                sha256File(blob) { checkActive(context) } != cached.digest
            ) {
                throw OpenCloudException(OpenCloudError.InvalidResponse)
            }
            requireAccess()
            val guardedSink =
                object : FilterOutputStream(sink) {
                    override fun write(value: Int) {
                        checkActive(context)
                        out.write(value)
                    }

                    override fun write(
                        bytes: ByteArray,
                        offset: Int,
                        length: Int,
                    ) {
                        checkActive(context)
                        out.write(bytes, offset, length)
                    }
                }
            val written = FileInputStream(blob).use { cipher.decryptContent(it, guardedSink, maxPlaintextBytes) }
            requireAccess()
            sink.flush()
            written
        }

    suspend fun preview(entry: VaultFolder): ByteArray {
        val output = WipingPreviewBuffer()
        return try {
            download(entry, output, VaultSession.MAX_PREVIEW_BYTES.toLong())
            output.toByteArray()
        } finally {
            output.wipe()
        }
    }

    suspend fun encodeDirectoryPath(path: String): String =
        withContext(Dispatchers.IO) {
            requireAccess()
            cipher.encryptPath(path)
        }

    suspend fun decodeDirectoryPath(encryptedRelativePath: String): String =
        withContext(Dispatchers.IO) {
            requireAccess()
            cipher.decryptPath(encryptedRelativePath)
        }

    /** One-shot copy for biometric enrollment after the local encrypted manifest was proven. */
    suspend fun exportVerifiedKeyMaterial(): ByteArray =
        withContext(Dispatchers.IO) {
            requireAccess()
            check(exported.compareAndSet(false, true)) { "Verified key material was already exported." }
            keyMaterial.copyOf()
        }

    @Suppress("ComplexCondition") // Each account and cache binding is required to fail closed.
    private suspend fun requireAccess() {
        currentCoroutineContext().ensureActive()
        checkActive(currentCoroutineContext())
        val current = accountFor(identity.accountId)
        if (current == null ||
            current != accountAtOpen ||
            !current.isActive ||
            endpoints.endpoint(current.serverUrl, allowQuery = false).toString() != identity.canonicalServer ||
            !File(directory, "manifest.enc").exists()
        ) {
            throw OpenCloudException(OpenCloudError.AuthenticationRequired)
        }
    }

    @Suppress("ComplexCondition") // Revocation, closure and credential permits must be checked together.
    private fun checkActive(context: CoroutineContext) {
        context.ensureActive()
        if (closed.get() ||
            !permit() ||
            accountGeneration != VaultOfflineRevocations.accountGeneration(identity.accountId) ||
            identityGeneration != VaultOfflineRevocations.identityGeneration(identity) ||
            VaultOfflineRevocations.accountBlocked(identity.accountId) ||
            VaultOfflineRevocations.identityBlocked(identity)
        ) {
            throw OpenCloudException(OpenCloudError.AccessDenied)
        }
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            issuedEntries.clear()
            keyMaterial.fill(0)
            cipher.close()
        }
    }
}

private class WipingPreviewBuffer : ByteArrayOutputStream(64 * 1024) {
    fun wipe() {
        buf.fill(0)
        reset()
    }
}

private fun joinEncrypted(
    parent: String,
    child: String,
): String =
    when {
        parent.isEmpty() -> child
        child.isEmpty() -> parent
        else -> "$parent/$child"
    }
