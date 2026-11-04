package eu.opencloud.android.next.core.sync

data class VaultLocation(
    val accountId: String,
    val title: String,
    val kind: VaultLocationKind,
    val driveId: String,
    /** Stable DAV file id for the vault root, distinct from Graph's drive id. */
    val remoteVaultId: String,
    /** Stable Graph root id for source revalidation. */
    val sourceRootId: String,
    val canonicalServer: String,
    val rootWebDavUrl: String,
    val vaultPath: String,
    val isVaultRoot: Boolean,
    val isDisabled: Boolean = false,
    val offlineOnly: Boolean = false,
    val offlineUnavailable: Boolean = false,
)

enum class VaultLocationKind {
    PERSONAL,
    SPACE,
    FOLDER_VAULT,
    SPACE_VAULT,
}

data class VaultFolder(
    val id: String,
    val name: String,
    val rawName: String,
    /** Plain relative path for navigation in an unlocked session or a plain source root. */
    val path: String,
    /** Opaque relative DAV path; never use as a local filesystem path. */
    val encryptedPath: String,
    val isFolder: Boolean,
    val size: Long,
    val strongETag: String?,
    val contentType: String? = null,
    val isVaultRoot: Boolean = false,
    internal val leaseId: String? = null,
)

enum class VaultUnlockFailure {
    PASSWORD_NOT_PROVEN,
}

/** The remote root may already exist; callers must show this state and must not auto-retry. */
class VaultCreationException(
    val remoteIdentifierOrPath: String,
    cause: Throwable,
) : IllegalStateException("Vault creation may have completed remotely; inspect before retrying.", cause)

class VaultUnlockException(
    val failure: VaultUnlockFailure,
) : IllegalStateException("The vault password could not be verified.")
