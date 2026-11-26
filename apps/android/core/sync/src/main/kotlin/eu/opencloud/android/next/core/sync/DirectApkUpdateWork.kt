package eu.opencloud.android.next.core.sync

import android.content.Context
import androidx.work.WorkManager

/** Leave transfer work intact when replacing a direct APK with the Play build. */
fun retireDirectApkUpdateWork(context: Context) {
    val work = WorkManager.getInstance(context.applicationContext)
    work.cancelUniqueWork("android-public-release-check")
    work.cancelUniqueWork("android-public-release-wifi-download")
}
