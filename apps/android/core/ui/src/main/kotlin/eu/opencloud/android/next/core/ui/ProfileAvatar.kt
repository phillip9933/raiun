package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import eu.opencloud.android.next.core.sync.AccountProfiles
import eu.opencloud.android.next.core.sync.ProfileAppearance

@Composable
fun ProfileAvatar(
    accountId: String,
    modifier: Modifier = Modifier,
    name: String = "",
) {
    val context = LocalContext.current
    val revision by AccountProfiles.revision.collectAsState()
    val profile by androidx.compose.runtime.key(accountId, name, revision) {
        produceState(ProfileAppearance(name)) {
            val cached = AccountProfiles.load(context, accountId, refresh = false)
            if (cached.name.isNotBlank()) value = cached
            val refreshed = AccountProfiles.load(context, accountId, refresh = true)
            if (refreshed.name.isNotBlank()) value = refreshed
        }
    }
    Surface(
        modifier.size(OpenCloudDimensions.AvatarSize),
        shape = CircleShape,
        color = MaterialTheme.colorScheme.primaryContainer,
    ) {
        Box(contentAlignment = Alignment.Center) {
            val bitmap = profile.image
            if (bitmap != null) {
                Image(bitmap.asImageBitmap(), null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop)
            } else {
                Text(
                    profile.name
                        .trim()
                        .firstOrNull()
                        ?.uppercase() ?: "?",
                    color = MaterialTheme.colorScheme.onPrimaryContainer,
                )
            }
        }
    }
}
