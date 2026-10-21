package eu.opencloud.android.next.core.designsystem

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.luminance
import androidx.compose.ui.res.painterResource
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
fun RaiunWordmark(modifier: Modifier = Modifier) {
    val ink =
        if (MaterialTheme.colorScheme.surface.luminance() <
            0.5f
        ) {
            OpenCloudColor.BrandMark
        } else {
            OpenCloudColor.BrandWordmark
        }
    Row(
        modifier,
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
    ) {
        Icon(
            painterResource(R.drawable.raiun_crest),
            contentDescription = null,
            modifier = Modifier.size(OpenCloudDimensions.WordmarkHeight),
            tint = ink,
        )
        Text("Raiun", style = MaterialTheme.typography.titleLarge, color = ink)
    }
}
