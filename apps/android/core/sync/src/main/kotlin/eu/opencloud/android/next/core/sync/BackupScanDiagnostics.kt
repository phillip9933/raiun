package eu.opencloud.android.next.core.sync

import android.content.Context
import android.content.SharedPreferences
import eu.opencloud.android.next.core.database.FolderBackupEntity
import eu.opencloud.android.next.core.model.cacheIdentity
import eu.opencloud.android.next.core.network.OpenCloudError
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged

/** Durable failure reasons only: no source names, paths, server responses or exception text. */
class BackupScanDiagnostics(
    context: Context,
) {
    private val preferences =
        context.applicationContext.getSharedPreferences(
            "backup-scan-diagnostics",
            Context.MODE_PRIVATE,
        )

    fun record(
        backup: FolderBackupEntity,
        failure: OpenCloudError,
        now: Long,
    ) = synchronized(lock) {
        val key = key(backup)
        if (preferences.getLong("$key/time", 0) > now) return@synchronized
        preferences
            .edit()
            .putString("$key/config", fingerprint(backup))
            .putString("$key/code", failure.diagnosticCode())
            .putLong("$key/time", now)
            .commit()
        Unit
    }

    fun read(backup: FolderBackupEntity): BackupScanFailure? {
        val key = key(backup)
        val snapshot = preferences.all
        val code = snapshot["$key/code"] as? String
        return if (snapshot["$key/config"] == fingerprint(backup) && code != null) {
            BackupScanFailure(backupScanError(code), snapshot["$key/time"] as? Long ?: 0)
        } else {
            null
        }
    }

    fun clear(
        backup: FolderBackupEntity,
        scannedAtEpochMillis: Long,
    ) = synchronized(lock) {
        val key = key(backup)
        if (preferences.getString("$key/config", null) == fingerprint(backup) &&
            preferences.getLong("$key/time", 0) <= scannedAtEpochMillis
        ) {
            removePrefix(key)
        }
    }

    fun clearAccount(accountId: String) = synchronized(lock) { removePrefix(cacheIdentity(accountId)) }

    fun forget(backup: FolderBackupEntity) = synchronized(lock) { removePrefix(key(backup)) }

    fun observe(backup: FolderBackupEntity): Flow<BackupScanFailure?> =
        callbackFlow {
            val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> trySend(read(backup)) }
            preferences.registerOnSharedPreferenceChangeListener(listener)
            trySend(read(backup))
            awaitClose { preferences.unregisterOnSharedPreferenceChangeListener(listener) }
        }.distinctUntilChanged()

    private fun removePrefix(prefix: String) {
        val editor = preferences.edit()
        preferences.all.keys
            .filter { it.startsWith("$prefix/") }
            .forEach(editor::remove)
        editor.commit()
    }

    private fun key(backup: FolderBackupEntity) = "${cacheIdentity(backup.accountId)}/${cacheIdentity(backup.id)}"

    private fun fingerprint(backup: FolderBackupEntity) =
        cacheIdentity(backup.copy(lastSafeScanEpochMillis = 0).toString())

    private companion object {
        val lock = Any()
    }
}

data class BackupScanFailure(
    val error: OpenCloudError,
    val occurredAtEpochMillis: Long,
)

/** Unknown or corrupt persisted codes always use fixed generic text. */
internal fun backupScanError(code: String): OpenCloudError = BACKUP_SCAN_ERRORS[code] ?: httpScanError(code)

private fun httpScanError(code: String): OpenCloudError {
    val status = Regex("(SERVER|HTTP)_([1-5][0-9]{2})").matchEntire(code)
    return when (status?.groupValues?.get(1)) {
        "SERVER" -> OpenCloudError.ServerFailure(status.groupValues[2].toInt(), null)
        "HTTP" -> OpenCloudError.HttpFailure(status.groupValues[2].toInt())
        else -> OpenCloudError.Unknown
    }
}

private val BACKUP_SCAN_ERRORS =
    mapOf(
        "CONNECTIVITY" to OpenCloudError.Connectivity,
        "TIMEOUT" to OpenCloudError.Timeout,
        "AUTHENTICATION_REQUIRED" to OpenCloudError.AuthenticationRequired,
        "CLIENT_REGISTRATION_REQUIRED" to OpenCloudError.ClientRegistrationRequired,
        "ACCESS_DENIED" to OpenCloudError.AccessDenied,
        "PASSWORD_REQUIRED" to OpenCloudError.PublicLinkPasswordRequired,
        "NOT_FOUND" to OpenCloudError.NotFound,
        "CONFLICT" to OpenCloudError.Conflict,
        "PRECONDITION_FAILED" to OpenCloudError.PreconditionFailed,
        "DIRECTORY_LISTING_TOO_LARGE" to OpenCloudError.DirectoryListingTooLarge,
        "INVALID_RESPONSE" to OpenCloudError.InvalidResponse,
        "LOCAL_STORAGE" to OpenCloudError.LocalStorage,
        "LOCAL_STORAGE_WRITE_FAILED" to OpenCloudError.LocalStorageWriteFailed,
        "SOURCE_UNAVAILABLE" to OpenCloudError.SourceUnavailable,
        "SOURCE_CHANGED" to OpenCloudError.SourceChanged,
        "SOURCE_PERMISSION" to OpenCloudError.SourcePermissionDenied,
        "REMOTE_QUOTA" to OpenCloudError.QuotaExceeded,
        "UNSUPPORTED" to OpenCloudError.Unsupported,
        "CLIENT_CERTIFICATE_REQUIRED" to OpenCloudError.ClientCertificateRequired,
        "NETWORK_ROUTE_CHANGED" to OpenCloudError.NetworkRouteChanged,
        "TRUST" to OpenCloudError.Trust,
        "REMOTE_NOT_READY" to OpenCloudError.NotReady(null),
        "RATE_LIMITED" to OpenCloudError.RateLimited(null),
    )
