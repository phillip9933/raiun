package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties

/** A fixed editor window: scrolling the form must never drag or dismiss it. */
@Composable
fun BackupEditorDialog(content: @Composable () -> Unit) {
    Dialog(
        onDismissRequest = {},
        properties =
            DialogProperties(
                dismissOnBackPress = false,
                dismissOnClickOutside = false,
                usePlatformDefaultWidth = false,
                decorFitsSystemWindows = false,
            ),
    ) {
        Surface(Modifier.fillMaxSize().safeDrawingPadding().imePadding(), content = content)
    }
}
