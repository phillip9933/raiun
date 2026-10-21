package eu.opencloud.android.next.feature.files

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics

/** Resolve localized text in composition before entering the non-composable semantics block. */
@Composable
internal fun Modifier.browserDescription(
    @StringRes id: Int,
    argument: String? = null,
): Modifier {
    val description = if (argument == null) stringResource(id) else stringResource(id, argument)
    return semantics { contentDescription = description }
}
