package eu.opencloud.android.next.feature.settings

import android.content.Context
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.work.WorkManager

const val appUpdatesAvailable = false

/** Retire the direct channel's persisted jobs on an in-place upgrade. */
fun initializeAppUpdates(context: Context) {
    val work = WorkManager.getInstance(context.applicationContext)
    work.cancelUniqueWork("android-public-release-check")
    work.cancelUniqueWork("android-public-release-wifi-download")
}

@Composable
fun AppUpdateChannelNotice() = Unit

@Composable
@Suppress("UNUSED_PARAMETER")
internal fun AppUpdateChannelRoute(onNavigateBack: () -> Unit) = Unit

@Composable
internal fun AppPrivacyPolicyLink() {
    val browser = LocalUriHandler.current
    TextButton(
        onClick = {
            runCatching {
                browser.openUri("https://github.com/phillip9933/raiun/blob/main/apps/android/PRIVACY.md")
            }
        },
    ) {
        Text(stringResource(R.string.play_privacy_policy))
    }
}
