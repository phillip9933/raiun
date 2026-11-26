package eu.opencloud.android.next.feature.settings

import android.content.Context
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.work.WorkManager

const val APP_UPDATES_AVAILABLE = false

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
    var openFailed by remember { mutableStateOf(false) }
    TextButton(
        onClick = {
            openFailed =
                try {
                    browser.openUri("https://github.com/phillip9933/raiun/blob/main/apps/android/PRIVACY.md")
                    false
                } catch (_: IllegalArgumentException) {
                    true
                }
        },
    ) {
        Text(stringResource(R.string.play_privacy_policy))
    }
    if (openFailed) {
        Text(
            text = stringResource(R.string.play_privacy_policy_open_failed),
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
            color = MaterialTheme.colorScheme.error,
        )
    }
}
