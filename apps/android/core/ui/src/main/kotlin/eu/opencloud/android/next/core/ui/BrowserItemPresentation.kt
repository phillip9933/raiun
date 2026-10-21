package eu.opencloud.android.next.core.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import eu.opencloud.android.next.core.datastore.FileDisplayOptions

fun browserDisplayName(
    name: String,
    isFolder: Boolean,
    options: FileDisplayOptions,
): String {
    if (options.showExtensions || isFolder || name.startsWith('.')) return name
    val dot = name.lastIndexOf('.')
    return if (dot > 0) name.substring(0, dot) else name
}

@Composable
fun BrowserItemMetadataText(
    text: String,
    modifier: Modifier = Modifier,
) {
    Text(
        text,
        modifier,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        style = MaterialTheme.typography.bodySmall,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}
