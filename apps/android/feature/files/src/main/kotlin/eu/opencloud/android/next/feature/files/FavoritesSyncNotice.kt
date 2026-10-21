package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun FavoritesSyncNotice(
    status: FavoritesSyncStatus,
    onRefresh: () -> Unit,
    detail: String? = null,
) {
    if (status == FavoritesSyncStatus.IDLE) return
    Column(Modifier.fillMaxWidth().padding(horizontal = OpenCloudDimensions.SpacingMd)) {
        val message =
            when (status) {
                FavoritesSyncStatus.RUNNING -> R.string.favorites_sync_running
                FavoritesSyncStatus.MORE -> R.string.favorites_sync_more
                FavoritesSyncStatus.FAILED -> R.string.favorites_sync_failed
                FavoritesSyncStatus.UNAVAILABLE -> R.string.favorites_sync_unavailable
                FavoritesSyncStatus.IDLE -> null
            }
        message?.let { Text(stringResource(it)) }
        if (status == FavoritesSyncStatus.FAILED && detail != null) Text(detail)
        if (status == FavoritesSyncStatus.RUNNING) {
            LinearProgressIndicator(Modifier.fillMaxWidth())
        } else {
            TextButton(onClick = onRefresh) {
                Text(
                    stringResource(
                        if (status ==
                            FavoritesSyncStatus.MORE
                        ) {
                            R.string.favorites_sync_continue
                        } else {
                            R.string.favorites_sync_refresh
                        },
                    ),
                )
            }
        }
    }
}
