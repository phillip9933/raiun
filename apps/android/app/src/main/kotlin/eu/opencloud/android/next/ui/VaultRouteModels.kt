package eu.opencloud.android.next.ui

import eu.opencloud.android.next.R

enum class VaultRouteMode { CATALOG, DISCOVERY, UNLOCK, CONTENTS }

enum class VaultPreviewKind { TEXT, IMAGE, PDF, UNSUPPORTED }

enum class VaultRouteError(
    val stringRes: Int,
    val retryable: Boolean,
) {
    CATALOG(R.string.vault_catalog_error, true),
    SERVER_RESPONSE(R.string.vault_server_response_error, true),
    DISCOVERY(R.string.vault_discovery_error, true),
    UNLOCK(R.string.vault_unlock_error, false),
    CONNECTION(R.string.vault_connection_error, true),
    SECURE_CONNECTION(R.string.vault_secure_connection_error, false),
    AUTHENTICATION(R.string.vault_authentication_error, false),
    ACCESS_DENIED(R.string.vault_access_denied_error, false),
    VAULT_CHANGED(R.string.vault_changed_error, false),
    UNLOCK_PROOF(R.string.vault_unlock_proof_error, false),
    CONTENTS(R.string.vault_contents_error, true),
    PREVIEW(R.string.vault_preview_error, false),
    BIOMETRIC(R.string.vault_biometric_unavailable, false),
    BIOMETRIC_SETUP(R.string.vault_biometric_setup_error, false),
    OPERATION(R.string.vault_operation_failed, false),
    OFFLINE_PREPARATION(R.string.vault_offline_preparation_failed, false),
    LOCAL_STORAGE(eu.opencloud.android.next.core.network.R.string.error_local_storage, false),
    LOCAL_SAVE(eu.opencloud.android.next.core.network.R.string.error_local_storage_write_failed, false),
    SOURCE_UNAVAILABLE(eu.opencloud.android.next.core.network.R.string.error_source_unavailable, false),
    SOURCE_CHANGED(eu.opencloud.android.next.core.network.R.string.error_source_changed, false),
    SOURCE_PERMISSION(eu.opencloud.android.next.core.network.R.string.error_source_permission_denied, false),
    INTEGRITY(eu.opencloud.android.next.core.network.R.string.error_download_integrity, false),
    SAVED_UNLOCK(eu.opencloud.android.next.core.network.R.string.error_encrypted_unlock_failed, false),
    OFFLINE_CHANGED(eu.opencloud.android.next.core.network.R.string.error_offline_snapshot_changed, false),
    OFFLINE_BUSY(eu.opencloud.android.next.core.network.R.string.error_offline_group_busy, false),
    LISTING_TOO_LARGE(eu.opencloud.android.next.core.network.R.string.error_directory_listing_too_large, false),
    OFFLINE_INDEX_FULL(eu.opencloud.android.next.core.network.R.string.error_encrypted_offline_index_full, false),
    REMOTE_QUOTA(eu.opencloud.android.next.core.network.R.string.error_quota_exceeded, false),
    NAME_CONFLICT(eu.opencloud.android.next.core.network.R.string.error_conflict, false),
    SERVER_BUSY(eu.opencloud.android.next.core.network.R.string.error_rate_limited, false),
    TRANSFER_UNLOCK_REQUIRED(R.string.vault_unlock_to_finish, false),
    EXPORT_FAILED(R.string.vault_export_failed, false),
    BIOMETRIC_CLEANUP(R.string.vault_biometric_cleanup_error, true),
    PHONE_LOCK_FAILED(R.string.vault_phone_lock_failed, false),
    PHONE_REMEMBER_FAILED(R.string.vault_phone_remember_failed, false),
}

data class VaultRouteLocation(
    val id: String,
    val title: String,
    val kind: VaultLocationKindUi,
    val isVaultRoot: Boolean,
    val offline: Boolean = false,
)

enum class VaultLocationKindUi(
    val stringRes: Int,
) {
    FOLDER_VAULT(R.string.vault_folder),
    SPACE_VAULT(R.string.vault_space),
    PERSONAL(R.string.vault_personal_files),
    SPACE(R.string.vault_space),
}

data class VaultRouteEntry(
    val id: String,
    val name: String,
    val path: String,
    val isFolder: Boolean,
    val isVaultRoot: Boolean,
    val size: Long,
    val contentType: String?,
    val offlineAvailable: Boolean? = null,
    val displaySize: Long? = size,
)

data class VaultRoutePreview(
    val title: String,
    val bytes: ByteArray,
    val kind: VaultPreviewKind,
    val editable: Boolean = false,
    val backing: EncryptedPreviewBacking? = null,
)

data class VaultDirectoryPageState(
    val offset: Long,
    val total: Long,
    val count: Int,
    val hasPrevious: Boolean,
) {
    val hasNext: Boolean get() = offset + count < total
}

data class VaultRouteState(
    val mode: VaultRouteMode = VaultRouteMode.CATALOG,
    val locations: List<VaultRouteLocation> = emptyList(),
    val entries: List<VaultRouteEntry> = emptyList(),
    val directoryPage: VaultDirectoryPageState? = null,
    val selectedLocation: VaultRouteLocation? = null,
    val selectedTitle: String? = null,
    val browseTitle: String? = null,
    val currentPath: String = "",
    val loading: Boolean = false,
    val error: VaultRouteError? = null,
    val biometricDiagnostic: String? = null,
    val phoneSessionIssueCode: String? = null,
    val biometricEnrolled: Boolean = false,
    val biometricNeedsForget: Boolean = false,
    val canEnrollBiometric: Boolean = false,
    val biometricOfferPending: Boolean = false,
    val phoneRememberOffer: Boolean = false,
    val lockingRememberedAccess: Boolean = false,
    val allowAutomaticBiometric: Boolean = true,
    val rootActionsVisible: Boolean = false,
    val offline: Boolean = false,
    val offlineCatalog: Boolean = false,
    val preview: VaultRoutePreview? = null,
    val previewSaving: Boolean = false,
    val previewSaveError: VaultRouteError? = null,
    val lockRevision: Long = 0,
    val transferConflict: VaultTransferConflict? = null,
    val destinationPickerPath: String? = null,
    val destinationPickerEntries: List<VaultRouteEntry> = emptyList(),
    val destinationPickerPage: VaultDirectoryPageState? = null,
    val destinationPickerLoading: Boolean = false,
    val destinationPickerError: VaultRouteError? = null,
    val preparingUpload: Boolean = false,
    val queuedUploadCount: Long = 0,
)

data class VaultRouteCallbacks(
    val onNavigateBack: () -> Unit,
    val onSelectLocation: (String) -> Unit,
    val onOpenDiscoveryFolder: (String) -> Unit,
    val onSelectVaultFolder: (String) -> Unit,
    val onUnlock: (CharArray) -> Unit,
    val onBiometricUnlock: () -> Unit,
    val onBiometricEnroll: () -> Unit,
    val onForgetBiometric: () -> Unit,
    val onOpenVaultFolder: (String) -> Unit,
    val onOpenPreview: (String) -> Unit,
    val onDismissPreview: () -> Unit,
    val onOpenWithPreview: () -> Unit = {},
    val onSavePreviewText: (VaultRoutePreview, ByteArray) -> Unit = { _, bytes -> bytes.fill(0) },
    val onSavePreviewTextRange: (
        VaultRoutePreview,
        Long,
        Long,
        ByteArray,
    ) -> Unit = { _, _, _, bytes -> bytes.fill(0) },
    val onLoadThumbnail: suspend (String) -> ByteArray? = { null },
    val onUp: () -> Unit,
    val onLock: () -> Unit,
    val onRetry: () -> Unit,
    val onDirectoryPage: (Boolean) -> Unit = {},
    val onShowHidden: (Boolean) -> Unit = {},
    val onResolveTransferConflict: (Boolean) -> Unit = {},
    val onLoadDestinationFolders: (String) -> Unit = {},
    val onBeginDestinationPicker: (String, String) -> Unit = { _, path -> onLoadDestinationFolders(path) },
    val onDestinationPage: (Boolean) -> Unit = {},
    val onOtherLocation: (String, Boolean) -> Unit = { _, _ -> },
    val onDismissDestinationPicker: () -> Unit = {},
    val onShowOffline: () -> Unit = {},
    val onKeepDirectoryOffline: () -> Unit = {},
    val onRemoveOffline: () -> Unit = {},
    val onShowOfflineActions: () -> Unit = {},
    val onCreateFolder: (String) -> Unit = {},
    val onUpload: () -> Unit = {},
    val onScan: () -> Unit = {},
    val onEntryAction: (String, VaultEntryAction, String?) -> Unit = { _, _, _ -> },
    val onAcceptBiometricOffer: () -> Unit = {},
    val onRememberOnPhone: () -> Unit = {},
    val onDeclineBiometricOffer: () -> Unit = {},
    val onShowRootActions: () -> Unit = {},
    val onManageLocation: () -> Unit = {},
    val onDismissRootActions: () -> Unit = {},
    val onRenameRoot: (String) -> Unit = {},
    val onDeleteRoot: () -> Unit = {},
)

data class VaultTransferConflict(
    val sourceId: String,
    val name: String,
    val path: String,
    val action: VaultEntryAction,
    val proposedName: String,
)
