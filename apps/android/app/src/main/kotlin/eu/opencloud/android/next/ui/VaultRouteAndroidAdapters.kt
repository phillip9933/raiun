package eu.opencloud.android.next.ui

import android.app.Application
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultKeyStore
import eu.opencloud.android.next.core.security.VaultPreferenceTargetKind
import eu.opencloud.android.next.core.security.VaultPreferences
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.sync.BoundaryEndpoint
import eu.opencloud.android.next.core.sync.VaultBoundaryEndpoint
import eu.opencloud.android.next.core.sync.VaultDirectorySnapshot
import eu.opencloud.android.next.core.sync.VaultFolder
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultOfflineSession
import eu.opencloud.android.next.core.sync.VaultOfflineStore
import eu.opencloud.android.next.core.sync.VaultRepository
import eu.opencloud.android.next.core.sync.VaultSession
import eu.opencloud.android.next.core.sync.completePendingOfflineDownloads
import eu.opencloud.android.next.core.sync.completePendingOfflineGroups
import eu.opencloud.android.next.core.sync.enqueueBackgroundOfflineDownload
import eu.opencloud.android.next.core.sync.enqueueBackgroundOfflineGroup
import eu.opencloud.android.next.core.sync.enqueueBackgroundReplacement
import eu.opencloud.android.next.core.sync.enqueueBackgroundUpload
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.map
import java.io.InputStream
import java.io.OutputStream
import javax.crypto.Cipher

private class AndroidVaultRouteDirectorySnapshot(
    private val snapshot: VaultDirectorySnapshot,
) : VaultRouteDirectorySnapshot {
    override val totalCount get() = snapshot.totalCount

    override suspend fun page(
        offset: Long,
        limit: Int,
    ) = snapshot.page(offset, limit)

    override fun close() = snapshot.close()
}

internal class AndroidVaultRouteRepository(
    private val application: Application,
) : VaultRouteRepository {
    private val repository = VaultRepository(application)
    private val offline = VaultOfflineStore(application)
    private val accounts =
        eu.opencloud.android.next.core.database.FileBrowserStore(
            eu.opencloud.android.next.core.database.FileBrowserDatabase
                .create(application),
        )

    override suspend fun unlockAccountSnapshot(accountId: String): Any? =
        accounts.account(accountId)?.takeIf {
            it.isActive
        }

    override suspend fun rememberBinding(accountId: String): VaultRememberBinding? {
        val groups = accounts.vaultOfflineGroups()
        val activeBeforeCapture = accounts.account(accountId)?.isActive == true
        val owner = if (activeBeforeCapture) groups.captureOwner(accountId) else null
        val ownerMatchesAccount = owner?.accountId == accountId
        val ownerCurrentAfterCapture = owner != null && ownerMatchesAccount && groups.isCurrentOwner(owner)
        val activeAfterCapture = accounts.account(accountId)?.isActive == true
        val ownerCurrentAfterAccountCheck = owner != null && groups.isCurrentOwner(owner)
        val currentOwner =
            owner?.takeIf {
                ownerCurrentAfterCapture && activeAfterCapture && ownerCurrentAfterAccountCheck
            }
        return currentOwner?.let { VaultRememberBinding(it.incarnation, it.accountIdentityDigest) }
    }

    override fun unlockCredentialPermit(accountId: String): () -> Boolean =
        eu.opencloud.android.next.core.security.AccountSessions
            .get(application)
            .beginLease(accountId)

    override suspend fun offlineLocations(accountId: String) = offline.locations(accountId)

    override suspend fun removeOffline(identity: VaultIdentity) {
        offline.remove(identity)
    }

    override suspend fun locations(accountId: String) = repository.locations(accountId)

    override suspend fun folders(
        accountId: String,
        location: VaultLocation,
        path: String,
    ) = repository.folders(accountId, location, path)

    override suspend fun unlock(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        password: CharArray,
    ): VaultRouteSession =
        if (target.offlineOnly) {
            AndroidOfflineVaultRouteSession(
                requireNotNull(offline.openWithPassword(accountId, target, password)),
                application,
                offline,
            )
        } else {
            AndroidVaultRouteSession(repository.unlock(accountId, target, vaultPath, password), offline, application)
        }

    override suspend fun unlockWithKeyMaterial(
        accountId: String,
        target: VaultLocation,
        vaultPath: String,
        keyMaterial: ByteArray,
    ): VaultRouteSession =
        if (target.offlineOnly) {
            AndroidOfflineVaultRouteSession(
                requireNotNull(offline.openWithKeyMaterial(accountId, target, keyMaterial)),
                application,
                offline,
            )
        } else {
            AndroidVaultRouteSession(
                repository.unlockWithKeyMaterial(accountId, target, vaultPath, keyMaterial),
                offline,
                application,
            )
        }
}

private class AndroidVaultRouteSession(
    private val session: VaultSession,
    private val offline: VaultOfflineStore,
    private val application: Application,
) : VaultRouteSession {
    override fun boundaryEndpoint(location: VaultLocation): BoundaryEndpoint = VaultBoundaryEndpoint(session, location)

    override suspend fun pinOffline(entry: VaultFolder) {
        if (entry.isFolder) {
            session.enqueueBackgroundOfflineGroup(application, entry.path, entry)
        } else {
            session.enqueueBackgroundOfflineDownload(application, entry)
        }
    }

    override fun observePendingOffline(): kotlinx.coroutines.flow.Flow<Unit> =
        pendingOfflineDownloads(application, identity)

    override suspend fun completePendingOffline() {
        session.completePendingOfflineGroups(application, offline)
        session.completePendingOfflineDownloads(application, offline)
        val revision = offlineListingRevision
        refreshPageOfflineStatus(lastPageEntries, revision)
    }

    override suspend fun pinOfflineDirectory(path: String) {
        session.enqueueBackgroundOfflineGroup(application, path)
    }

    override val identity get() = session.identity

    private var savedFiles: List<VaultFolder>? = null
    private var lastPageEntries: List<VaultFolder> = emptyList()
    private var offlineListingRevision = 0L

    override fun offlineAvailable(entry: VaultFolder): Boolean? =
        if (entry.isFolder) {
            null
        } else {
            savedFiles?.any {
                it.encryptedPath == entry.encryptedPath && it.strongETag == entry.strongETag
            }
        }

    override suspend fun list(path: String): List<VaultFolder> {
        ++offlineListingRevision
        lastPageEntries = emptyList()
        savedFiles = null
        return session.list(path)
    }

    override suspend fun openDirectory(
        path: String,
        showHidden: Boolean,
        excludedPath: String?,
    ): VaultRouteDirectorySnapshot {
        val snapshot = session.openDirectory(path, showHidden, excludedPath)
        val revision = ++offlineListingRevision
        return object : VaultRouteDirectorySnapshot {
            override val totalCount get() = snapshot.totalCount

            override suspend fun page(
                offset: Long,
                limit: Int,
            ): List<VaultFolder> {
                var delivered = false
                try {
                    val entries = snapshot.page(offset, limit)
                    lastPageEntries = entries
                    refreshPageOfflineStatus(entries, revision)
                    currentCoroutineContext().ensureActive()
                    delivered = true
                    return entries
                } finally {
                    if (!delivered) snapshot.close()
                }
            }

            override fun close() {
                if (offlineListingRevision == revision) {
                    offlineListingRevision++
                    lastPageEntries = emptyList()
                    savedFiles = null
                }
                snapshot.close()
            }
        }
    }

    @Suppress("TooGenericExceptionCaught") // Optional status cannot block live encrypted browsing.
    private suspend fun refreshPageOfflineStatus(entries: List<VaultFolder>, revision: Long) {
        val refreshed =
            try {
                session.offlineFiles(offline, entries)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null
            }
        if (revision == offlineListingRevision) savedFiles = refreshed
    }

    override suspend fun preview(entry: VaultFolder) = session.preview(entry)

    override suspend fun exportVerifiedKeyMaterial() = session.exportVerifiedKeyMaterial()

    override suspend fun encodeDirectoryPath(plainPath: String) = session.encodeDirectoryPath(plainPath)

    override suspend fun decodeDirectoryPath(encryptedRelativePath: String) =
        session.decodeDirectoryPath(encryptedRelativePath)

    override suspend fun createFolder(
        parentPath: String,
        name: String,
    ) = session.createFolder(parentPath, name)

    override suspend fun delete(entry: VaultFolder) = session.delete(entry)

    override suspend fun rename(
        entry: VaultFolder,
        newName: String,
    ) = session.rename(entry, newName)

    override suspend fun move(
        entry: VaultFolder,
        destinationPath: String,
        newName: String,
    ) = session.move(entry, destinationPath, newName)

    override suspend fun copy(
        entry: VaultFolder,
        destinationPath: String,
        newName: String,
    ) = session.copy(entry, destinationPath, newName)

    override suspend fun upload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ) = session.upload(parentPath, name, source, size, mimeType)

    override suspend fun queueUpload(
        parentPath: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ) {
        session.enqueueBackgroundUpload(application, parentPath, name, source, size)
    }

    override suspend fun replaceText(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ): VaultFolder =
        session.upload(
            parentPath = entry.path.trim('/').substringBeforeLast('/', ""),
            name = entry.name,
            source = source,
            size = size,
            mimeType = entry.contentType,
            overwrite = entry,
        )

    override suspend fun queueReplacement(
        entry: VaultFolder,
        source: InputStream,
        size: Long,
    ) {
        session.enqueueBackgroundReplacement(application, entry, source, size)
    }

    override suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long,
    ) = session.download(entry, sink, maxPlaintextBytes)

    override suspend fun renameVaultRoot(newName: String) = session.renameVaultRoot(newName)

    override suspend fun deleteVaultRoot() = session.deleteVaultRoot()

    override fun close() {
        savedFiles = null
        lastPageEntries = emptyList()
        session.close()
    }
}

internal class AndroidVaultBiometricKeyStore(
    private val store: VaultKeyStore,
) : VaultBiometricKeyStore {
    override fun hasEnrollment(identity: VaultIdentity) = store.hasEnrollment(identity)

    override fun prepareEnrollment(identity: VaultIdentity) = store.prepareEnrollment(identity)

    override fun completeEnrollment(
        identity: VaultIdentity,
        cipher: Cipher,
        keyMaterial: ByteArray,
    ) = store.completeEnrollment(identity, cipher, keyMaterial)

    override fun cancelEnrollment(identity: VaultIdentity) = store.cancelEnrollment(identity)

    override fun prepareUnlock(identity: VaultIdentity) = store.prepareUnlock(identity)

    override fun completeUnlock(
        identity: VaultIdentity,
        cipher: Cipher,
    ) = store.completeUnlock(identity, cipher)

    override fun cancelUnlock(identity: VaultIdentity) = store.cancelUnlock(identity)

    override fun forget(identity: VaultIdentity) = store.forget(identity)
}

internal class AndroidVaultOfferPreferences(
    application: Application,
) : VaultOfferPreferences {
    private val preferences = VaultPreferences(application)

    override fun status(identity: VaultIdentity) = preferences.status(identity)

    override fun remember(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    ) = preferences.remember(identity, title, targetKind)

    override fun decline(
        identity: VaultIdentity,
        title: String,
        targetKind: VaultPreferenceTargetKind,
    ) = preferences.decline(identity, title, targetKind)

    override fun remove(identity: VaultIdentity) = preferences.remove(identity)
}

private class AndroidOfflineVaultRouteSession(
    private val session: VaultOfflineSession,
    private val application: Application,
    private val offline: VaultOfflineStore,
) : VaultRouteSession {
    override val isOffline = true
    override val identity get() = session.identity

    override fun observePendingOffline(): kotlinx.coroutines.flow.Flow<Unit> =
        pendingOfflineDownloads(application, identity)

    override suspend fun completePendingOffline() {
        session.completePendingOfflineGroups(application, offline)
        session.completePendingOfflineDownloads(application, offline)
    }

    override suspend fun list(path: String) = session.list(path)

    override suspend fun openDirectory(
        path: String,
        showHidden: Boolean,
        excludedPath: String?,
    ): VaultRouteDirectorySnapshot =
        AndroidVaultRouteDirectorySnapshot(session.openDirectory(path, showHidden, excludedPath))

    override suspend fun preview(entry: VaultFolder) = session.preview(entry)

    override suspend fun exportVerifiedKeyMaterial() = session.exportVerifiedKeyMaterial()

    override suspend fun encodeDirectoryPath(plainPath: String) = session.encodeDirectoryPath(plainPath)

    override suspend fun decodeDirectoryPath(encryptedRelativePath: String) =
        session.decodeDirectoryPath(encryptedRelativePath)

    override suspend fun download(
        entry: VaultFolder,
        sink: OutputStream,
        maxPlaintextBytes: Long,
    ) = session.download(entry, sink, maxPlaintextBytes)

    override fun close() = session.close()
}

private fun pendingOfflineDownloads(
    application: Application,
    identity: VaultIdentity,
): kotlinx.coroutines.flow.Flow<Unit> {
    val store =
        eu.opencloud.android.next.core.database.FileBrowserStore(
            eu.opencloud.android.next.core.database.FileBrowserDatabase
                .create(application),
        )
    return kotlinx.coroutines.flow
        .combine(
            store.observeAwaitingCiphertextDownloads(identity.accountId, "vault-offline:${identity.remoteVaultId}"),
            store.vaultOfflineGroups().observeAwaiting(identity.accountId, identity.driveId, identity.remoteVaultId),
        ) { files, group ->
            listOfNotNull(files, group).joinToString("|").takeIf { it.isNotEmpty() }
        }.pendingOfflineCompletionEvents()
}

/** An empty queue separates attempts, even when a retry retains the same transfer identity. */
internal fun Flow<String?>.pendingOfflineCompletionEvents(): Flow<Unit> =
    distinctUntilChanged()
        .filterNotNull()
        .map { Unit }
