package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultPreferenceStatus
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher

interface VaultRouteRepository {
    /** Immutable non-secret account row; absent adapters opt out of remembered-key restore. */
    suspend fun unlockAccountSnapshot(accountId: String): Any? = null

    /** Durable Room owner scope for device-remember binding; absent adapters opt out safely. */
    suspend fun rememberBinding(accountId: String): VaultRememberBinding? = null

    fun unlockCredentialPermit(accountId: String): () -> Boolean = { false }

    suspend fun offlineLocations(accountId: String): List<VaultLocation> = emptyList()

    suspend fun removeOffline(identity: VaultIdentity) = Unit

    suspend fun locations(accountId: String): List<VaultLocation>

    suspend fun folders(
        accountId: String,
        location: VaultLocation,
        path: String,
    ): List<VaultFolder>

    suspend fun unlock(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        password: CharArray,
    ): VaultRouteSession

    suspend fun unlockWithKeyMaterial(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        keyMaterial: ByteArray,
    ): VaultRouteSession
}

interface VaultRouteDirectorySnapshot : AutoCloseable {
    val totalCount: Long

    suspend fun page(
        offset: Long = 0,
        limit: Int = VAULT_DIRECTORY_PAGE_SIZE,
    ): List<VaultFolder>

    override fun close()
}

/** Compatibility for small legacy test doubles. Android adapters always override openDirectory. */
private class SmallVaultRouteDirectorySnapshot(
    entries: List<VaultFolder>,
    showHidden: Boolean,
    excludedPath: String?,
) : VaultRouteDirectorySnapshot {
    private val entries =
        entries
            .also { require(it.size <= 256) }
            .filter { showHidden || !it.name.startsWith('.') }
            .filter { excludedPath == null || it.path != excludedPath && !it.path.startsWith(excludedPath + "/") }
            .sortedWith(
                compareBy<VaultFolder> { !it.isFolder }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
                    .thenBy { it.name }
                    .thenBy { it.encryptedPath }
                    .thenBy { it.id },
            )
    private var closed = false
    override val totalCount: Long get() = entries.size.toLong()

    override suspend fun page(
        offset: Long,
        limit: Int,
    ): List<VaultFolder> {
        check(!closed)
        require(offset >= 0 && limit in 1..256)
        return entries.drop(offset.coerceAtMost(entries.size.toLong()).toInt()).take(limit)
    }

    override fun close() {
        closed = true
    }
}

interface VaultRouteSession {
    fun boundaryEndpoint(location: VaultLocation): BoundaryEndpoint = unsupportedVaultMutation()

    fun observePendingOffline(): kotlinx.coroutines.flow.Flow<Unit> = kotlinx.coroutines.flow.emptyFlow()

    suspend fun completePendingOffline() = Unit

    fun offlineAvailable(entry: VaultFolder): Boolean? = if (isOffline) true else null

    val isOffline: Boolean get() = false

    suspend fun pinOffline(entry: VaultFolder): Unit = unsupportedVaultMutation()

    suspend fun pinOfflineDirectory(path: String): Unit = unsupportedVaultMutation()

    val identity: VaultIdentity

    suspend fun list(path: String): List<VaultFolder>

    suspend fun openDirectory(
        path: String,
        showHidden: Boolean = false,
        excludedPath: String? = null,
    ): VaultRouteDirectorySnapshot = SmallVaultRouteDirectorySnapshot(list(path), showHidden, excludedPath)

    suspend fun preview(entry: VaultFolder): ByteArray

    suspend fun exportVerifiedKeyMaterial(): ByteArray

    suspend fun encodeDirectoryPath(plainPath: String): String = plainPath

    suspend fun decodeDirectoryPath(encryptedRelativePath: String): String = encryptedRelativePath

    suspend fun createFolder(
        parentPath: String,
        name: String,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun delete(entry: VaultFolder): Unit = unsupportedVaultMutation()

    suspend fun rename(
        entry: VaultFolder,
        newName: String,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun move(
        entry: VaultFolder,
        destinationPath: String,
        newName: String = entry.name,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun copy(
        entry: VaultFolder,
        destinationPath: String,
        newName: String = entry.name,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun upload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun queueUpload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): Unit = unsupportedVaultMutation()

    suspend fun replaceText(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ): VaultFolder = unsupportedVaultMutation()

    suspend fun queueReplacement(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ): Unit = unsupportedVaultMutation()

    suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long,
    ): Long = unsupportedVaultMutation()

    suspend fun renameVaultRoot(newName: String): VaultLocation = unsupportedVaultMutation()

    suspend fun deleteVaultRoot(): Unit = unsupportedVaultMutation()

    fun close()
}

private fun <T> unsupportedVaultMutation(): T = throw UnsupportedOperationException("Vault operation is unavailable.")

interface VaultBiometricKeyStore {
    fun hasEnrollment(identity: VaultIdentity): Boolean

    fun prepareEnrollment(identity: VaultIdentity): Cipher

    fun completeEnrollment(
        identity: VaultIdentity,
        cipher: Cipher,
        keyMaterial: ByteArray,
    )

    fun cancelEnrollment(identity: VaultIdentity)

    fun prepareUnlock(identity: VaultIdentity): Cipher

    fun completeUnlock(
        identity: VaultIdentity,
        cipher: Cipher,
    ): ByteArray

    fun cancelUnlock(identity: VaultIdentity)

    fun forget(identity: VaultIdentity)
}

internal interface VaultOfferPreferences {
    fun status(identity: VaultIdentity): VaultPreferenceStatus?

    fun remember(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    )

    fun decline(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    )

    fun remove(identity: VaultIdentity)
}
