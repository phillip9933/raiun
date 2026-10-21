package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource

@Composable
fun ScannerLocationButton(
    label: String,
    enabled: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    OutlinedButton(onClick = onClick, enabled = enabled, modifier = modifier.fillMaxWidth()) {
        Icon(Icons.Default.Folder, null)
        Column(Modifier.weight(1f)) {
            Text(stringResource(R.string.scanner_location_title), style = MaterialTheme.typography.labelMedium)
            Text(label, style = MaterialTheme.typography.bodyLarge)
        }
    }
}
