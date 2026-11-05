package eu.opencloud.android.next.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import eu.opencloud.android.next.R
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun UnlockContent(
    state: VaultRouteState,
    callbacks: VaultRouteCallbacks,
    modifier: Modifier = Modifier,
) {
    var password by remember(state.selectedLocation?.id, state.mode, state.lockRevision) { mutableStateOf("") }
    var passwordVisible by remember(
        state.selectedLocation?.id,
        state.mode,
        state.lockRevision,
    ) { mutableStateOf(false) }
    if (state.loading) {
        Column(
            modifier = modifier.fillMaxSize().semantics { liveRegion = LiveRegionMode.Polite },
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm, Alignment.CenterVertically),
        ) {
            CircularProgressIndicator()
            Text(
                stringResource(
                    if (state.lockingRememberedAccess) {
                        R.string.vault_locking_remembered_access
                    } else {
                        R.string.vault_verifying_key
                    },
                ),
                style = MaterialTheme.typography.bodyLarge,
            )
        }
    } else {
        Column(modifier = modifier, verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
            OutlinedTextField(
                value = password,
                onValueChange = { password = it },
                label = { Text(stringResource(R.string.vault_password_label)) },
                singleLine = true,
                visualTransformation =
                    if (passwordVisible) {
                        VisualTransformation.None
                    } else {
                        PasswordVisualTransformation()
                    },
                trailingIcon = {
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(
                            if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                            stringResource(
                                if (passwordVisible) R.string.vault_hide_password else R.string.vault_show_password,
                            ),
                        )
                    }
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                modifier = Modifier.fillMaxWidth(),
            )
            FlowRow(
                horizontalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm),
                verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXs),
            ) {
                Button(
                    enabled = password.isNotEmpty(),
                    onClick = {
                        val suppliedPassword = password.toCharArray()
                        password = ""
                        passwordVisible = false
                        callbacks.onUnlock(suppliedPassword)
                    },
                ) { Text(stringResource(R.string.vault_unlock_action)) }
                if (state.biometricEnrolled) {
                    TextButton(onClick = callbacks.onBiometricUnlock) {
                        Text(stringResource(R.string.vault_biometric_unlock))
                    }
                }
                if (state.biometricEnrolled || state.biometricNeedsForget) {
                    TextButton(onClick = callbacks.onForgetBiometric) {
                        Text(stringResource(R.string.vault_biometric_forget))
                    }
                }
            }
        }
    }
}
