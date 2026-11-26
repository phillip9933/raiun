package eu.opencloud.android.next.feature.settings

import android.content.Context
import androidx.compose.runtime.Composable

const val APP_UPDATES_AVAILABLE = true

fun initializeAppUpdates(context: Context) {
    RaiunUpdates.get(context).initialize()
}

@Composable
fun AppUpdateChannelNotice() {
    AppUpdateNotice()
}

@Composable
internal fun AppUpdateChannelRoute(onNavigateBack: () -> Unit) {
    AppUpdatesRoute(onNavigateBack = onNavigateBack)
}

@Composable
internal fun AppPrivacyPolicyLink() = Unit
