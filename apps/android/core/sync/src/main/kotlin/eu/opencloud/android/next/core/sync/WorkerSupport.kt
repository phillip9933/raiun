package eu.opencloud.android.next.core.sync

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.work.ForegroundInfo
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.security.KeystoreCredentialStore
import eu.opencloud.android.next.core.security.TlsPolicy
import okhttp3.Credentials
import okhttp3.OkHttpClient

class WorkerAuthorizationProvider(
    private val context: Context,
) {
    fun authorization(account: AccountEntity): String {
        val credentials = KeystoreCredentialStore(context)
        if (account.authenticationType == "BASIC") {
            val username = credentials.readBasicUsername(account.id) ?: account.userId
            return Credentials.basic(username, requireNotNull(credentials.readBasicPassword(account.id)))
        }
        val usable =
            eu.opencloud.android.next.core.security.AccountSessions.get(context).tokens(account.id) { current ->
                val binding =
                    credentials.readClientRegistration("account:${account.id}")
                        ?: throw eu.opencloud.android.next.core.network.OpenCloudException(
                            eu.opencloud.android.next.core.network.OpenCloudError.AuthenticationRequired,
                        )
                if (binding.serverUrl != account.serverUrl ||
                    binding.issuer != account.oidcIssuer ||
                    binding.tokenEndpoint != account.oidcTokenEndpoint
                ) {
                    throw eu.opencloud.android.next.core.network.OpenCloudException(
                        eu.opencloud.android.next.core.network.OpenCloudError.AuthenticationRequired,
                    )
                }
                val api = OpenCloudApi(TlsPolicy(context).applyTo(OkHttpClient.Builder().build(), account.serverUrl))
                api.refresh(
                    OidcConfiguration(
                        binding.issuer,
                        binding.authorizationEndpoint,
                        binding.tokenEndpoint,
                        null,
                        binding.clientId,
                        emptyList(),
                    ),
                    requireNotNull(current.refreshToken),
                )
            }
        return "${usable.tokenType} ${usable.accessToken}"
    }
}

internal object TransferNotifications {
    const val LARGE_TRANSFER_BYTES = 10L * 1024 * 1024
    private const val CHANNEL_ID = "opencloud-transfers"

    fun foregroundInfo(
        context: Context,
        transferId: String,
        title: String,
        bytes: Long,
        total: Long,
    ): ForegroundInfo {
        val localized = ContextCompat.getContextForLanguage(context)
        val manager = context.getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                localized.getString(R.string.transfer_notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            ),
        )
        val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        val pendingIntent =
            launchIntent?.let {
                PendingIntent.getActivity(
                    context,
                    transferId.hashCode(),
                    it,
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                )
            }
        val progress = if (total > 0) ((bytes.coerceAtMost(total) * 100) / total).toInt() else 0
        val notification =
            android.app.Notification
                .Builder(context, CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentTitle(title)
                .setContentText(
                    if (total >
                        0
                    ) {
                        "$progress%"
                    } else {
                        localized.getString(R.string.transfer_notification_progress)
                    },
                ).setProgress(100, progress, total <= 0)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .apply { pendingIntent?.let(::setContentIntent) }
                .build()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ForegroundInfo(
                transferId.hashCode(),
                notification,
                android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            ForegroundInfo(transferId.hashCode(), notification)
        }
    }
}
