package eu.opencloud.android.next.feature.files

import android.text.format.Formatter
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

internal val ResourceEntity.selectionKey: String get() = "$spaceId\u0000$remoteId"

internal fun downloadedBytes(
    context: android.content.Context,
    resources: List<ResourceEntity>,
): Long =
    resources
        .mapNotNull { resource ->
            eu.opencloud.android.next.core.model.validatedCachedFile(
                eu.opencloud.android.next.core.model.resourceCacheDirectory(
                    context.filesDir,
                    resource.accountId,
                    resource.spaceId,
                ),
                resource.localPath,
                resource.sizeBytes,
            )
        }.distinctBy { it.path }
        .sumOf { it.length() }

@Composable
@Suppress("LongParameterList")
internal fun StorageSummary(
    title: String,
    bytes: Long,
    action: String,
    enabled: Boolean,
    onAction: () -> Unit,
    explanation: String,
    incomplete: Boolean = false,
) {
    val size = Formatter.formatShortFileSize(LocalContext.current, bytes)
    val amount =
        when {
            incomplete && bytes == 0L -> "Size unavailable"
            incomplete -> "≥ $size"
            else -> size
        }
    Surface(color = MaterialTheme.colorScheme.surfaceContainerLow) {
        Column(
            Modifier.fillMaxWidth().padding(
                horizontal = OpenCloudDimensions.SpacingMd,
                vertical = OpenCloudDimensions.SpacingXs,
            ),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.bodyMedium)
                    Text(
                        amount,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier =
                            Modifier.semantics {
                                contentDescription =
                                    if (incomplete) "$amount; the server did not report all item sizes" else amount
                            },
                    )
                }
                FilledTonalButton(
                    onClick = onAction,
                    enabled = enabled,
                    modifier = Modifier.weight(1.15f),
                    contentPadding =
                        PaddingValues(
                            horizontal = OpenCloudDimensions.SpacingSm,
                            vertical = OpenCloudDimensions.SpacingXs,
                        ),
                    shape = RoundedCornerShape(OpenCloudDimensions.ContentCornerRadius),
                    colors =
                        ButtonDefaults.filledTonalButtonColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer,
                            contentColor = MaterialTheme.colorScheme.onErrorContainer,
                        ),
                ) { Text(action, textAlign = androidx.compose.ui.text.style.TextAlign.Center) }
            }
            Text(
                explanation,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
