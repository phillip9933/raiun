package eu.opencloud.android.next.feature.files

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

/** Password text stays in transient Compose state; only a caller-owned CharArray crosses the callback. */
@Composable
@Suppress("LongParameterList") // Contextual title/label, explicit creation callbacks, dismissal and busy state.
internal fun BrowserCreationDialog(
    title: String,
    encryptLabel: String,
    onPlainCreate: (String) -> Unit,
    onEncryptedCreate: ((String, CharArray) -> Unit)?,
    onDismiss: () -> Unit,
    busy: Boolean = false,
) {
    var name by remember { mutableStateOf("") }
    var encrypted by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var confirmationVisible by remember { mutableStateOf(false) }
    val lifecycleOwner = LocalLifecycleOwner.current

    fun clearSecrets() {
        password = ""
        confirmation = ""
        passwordVisible = false
        confirmationVisible = false
    }

    DisposableEffect(Unit) { onDispose { clearSecrets() } }
    DisposableEffect(lifecycleOwner) {
        val observer =
            LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_STOP) clearSecrets()
            }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    val valid =
        name.isNotBlank() &&
            (!encrypted || (password.isNotEmpty() && password == confirmation && onEncryptedCreate != null))
    AlertDialog(
        onDismissRequest = {
            clearSecrets()
            onDismiss()
        },
        properties = DialogProperties(securePolicy = SecureFlagPolicy.SecureOn),
        containerColor = MaterialTheme.colorScheme.surfaceContainerHigh,
        title = { Text(title) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
            ) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text(stringResource(R.string.browser_name)) },
                    singleLine = true,
                )
                if (onEncryptedCreate != null) {
                    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs)) {
                        Row(
                            modifier =
                                Modifier.fillMaxWidth().toggleable(
                                    value = encrypted,
                                    enabled = !busy,
                                    role = Role.Switch,
                                    onValueChange = {
                                        encrypted = it
                                        if (!it) clearSecrets()
                                    },
                                ),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Text(encryptLabel, modifier = Modifier.weight(1f))
                            Switch(
                                checked = encrypted,
                                onCheckedChange = null,
                                enabled = !busy,
                            )
                        }
                        Text(
                            text = stringResource(R.string.browser_encrypt_new_summary),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(start = OpenCloudDimensions.SpacingMd),
                        )
                    }
                }
                if (encrypted) {
                    Text(stringResource(R.string.browser_encrypt_keep_password))
                    PasswordField(
                        value = password,
                        onValueChange = { password = it },
                        label = stringResource(R.string.browser_encrypt_password),
                        visible = passwordVisible,
                        onToggleVisibility = { passwordVisible = !passwordVisible },
                    )
                    PasswordField(
                        value = confirmation,
                        onValueChange = { confirmation = it },
                        label = stringResource(R.string.browser_encrypt_confirm_password),
                        visible = confirmationVisible,
                        onToggleVisibility = { confirmationVisible = !confirmationVisible },
                    )
                    if (confirmation.isNotEmpty() && password != confirmation) {
                        Text(stringResource(R.string.browser_encrypt_password_mismatch))
                    }
                }
            }
        },
        confirmButton = {
            Button(
                enabled = valid && !busy,
                onClick = {
                    val cleanName = name.trim()
                    if (encrypted) {
                        val secret = password.toCharArray()
                        try {
                            requireNotNull(onEncryptedCreate)(cleanName, secret)
                        } finally {
                            secret.fill('\u0000')
                            clearSecrets()
                        }
                    } else {
                        onPlainCreate(cleanName)
                    }
                    onDismiss()
                },
            ) { Text(stringResource(R.string.browser_create)) }
        },
        dismissButton = {
            TextButton(onClick = {
                clearSecrets()
                onDismiss()
            }) { Text(stringResource(R.string.browser_cancel)) }
        },
    )
}

@Composable
private fun PasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    visible: Boolean,
    onToggleVisibility: () -> Unit,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        singleLine = true,
        trailingIcon = {
            IconButton(onClick = onToggleVisibility) {
                Icon(
                    if (visible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                    contentDescription =
                        stringResource(
                            if (visible) {
                                R.string.browser_encrypt_hide_password
                            } else {
                                R.string.browser_encrypt_show_password
                            },
                        ),
                )
            }
        },
    )
}
