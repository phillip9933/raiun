package eu.opencloud.android.next.core.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

/** Shared Material layout for ordinary and encrypted text editing. State and persistence stay with callers. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
@Suppress("LongParameterList") // Presentation labels, state, and independent caller-owned actions.
fun SharedTextEditorScreen(
    title: String,
    text: String,
    fieldLabel: String,
    backDescription: String,
    saveLabel: String,
    saveEnabled: Boolean,
    backEnabled: Boolean,
    readOnly: Boolean,
    showTextField: Boolean,
    onTextChange: (String) -> Unit,
    onBack: () -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
    beforeEditor: @Composable ColumnScope.() -> Unit = {},
    footerStatus: @Composable () -> Unit = {},
    footerActions: @Composable RowScope.() -> Unit = {},
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1) },
                navigationIcon = {
                    IconButton(onClick = onBack, enabled = backEnabled) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, backDescription)
                    }
                },
                actions = {
                    FilledTonalButton(onClick = onSave, enabled = saveEnabled) {
                        Text(saveLabel)
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .imePadding()
                .padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
        ) {
            beforeEditor()
            if (showTextField) {
                OutlinedTextField(
                    value = text,
                    onValueChange = onTextChange,
                    readOnly = readOnly,
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    label = { Text(fieldLabel) },
                )
            }
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                Box(Modifier.weight(1f)) { footerStatus() }
                footerActions()
            }
        }
    }
}
