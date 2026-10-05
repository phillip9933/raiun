package eu.opencloud.android.next

import android.app.Application
import eu.opencloud.android.next.core.sync.TransferStartup
import eu.opencloud.android.next.core.sync.VaultExternalCopyStore

class OpenCloudApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        registerReceiver(
            object : android.content.BroadcastReceiver() {
                override fun onReceive(
                    context: android.content.Context,
                    intent: android.content.Intent,
                ) {
                    eu.opencloud.android.next.core.security.AppLock(context).apply {
                        lock()
                        notifyProvider()
                    }
                }
            },
            android.content.IntentFilter(android.content.Intent.ACTION_SCREEN_OFF),
        )
        VaultExternalCopyStore.initializeProcess(this)
        // Interrupted scanner output is private, non-resumable, and removed before another scanner run.
        runCatching {
            eu.opencloud.android.next.core.sync
                .VaultScanTempStore(this)
        }
        TransferStartup.initialize(this)
    }
}
