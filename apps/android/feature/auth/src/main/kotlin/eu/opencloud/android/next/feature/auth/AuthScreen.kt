package eu.opencloud.android.next.feature.auth

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
@Suppress("CyclomaticComplexMethod", "LongParameterList")
fun AuthScreen(
    state: AuthUiState,
    devLogin: DevLoginConfiguration?,
    onDiscover: (String, String?) -> Unit,
    onBasicLogin: (String, String) -> Unit,
    onDevLogin: (DevLoginConfiguration) -> Unit,
    onBeginOidc: () -> Unit,
    modifier: Modifier = Modifier,
    onAppTokenLogin: ((String, String, String) -> Unit)? = null,
) {
    var useAppToken by rememberSaveable { mutableStateOf(false) }
    var serverUrl by rememberSaveable { mutableStateOf("") }
    var staticClientId by rememberSaveable { mutableStateOf("") }
    var username by rememberSaveable { mutableStateOf("") }
    var password by remember { mutableStateOf("") }

    Column(
        modifier =
            modifier
                .fillMaxSize()
                .safeDrawingPadding()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(OpenCloudDimensions.SpacingXl),
        verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingMd),
    ) {
        Text(stringResource(R.string.auth_connect_title), style = MaterialTheme.typography.headlineSmall)
        Text(
            stringResource(R.string.auth_server_discovery_description),
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedTextField(
            value = serverUrl,
            onValueChange = { serverUrl = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.auth_server_address)) },
            singleLine = true,
        )
        onAppTokenLogin?.let { login ->
            TextButton(onClick = { useAppToken = !useAppToken }, enabled = !state.isLoading) {
                Text(
                    stringResource(
                        if (useAppToken) R.string.auth_use_browser_sign_in else R.string.auth_use_app_password,
                    ),
                )
            }
            if (useAppToken) {
                AppTokenFields(serverUrl, state.isLoading, state.error, login)
                return@Column
            }
        }
        OutlinedTextField(
            value = staticClientId,
            onValueChange = { staticClientId = it },
            modifier = Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.auth_client_id)) },
            singleLine = true,
        )
        Button(
            onClick = { onDiscover(serverUrl, staticClientId.trim().ifBlank { null }) },
            enabled = serverUrl.isNotBlank() && !state.isLoading,
        ) {
            Text(stringResource(R.string.auth_continue))
        }
        devLogin?.let { configuration ->
            Button(
                onClick = { onDevLogin(configuration) },
                enabled = configuration.isConfigured && !state.isLoading,
            ) {
                Text(stringResource(R.string.auth_dev_login))
            }
            if (!configuration.isConfigured) {
                Text(
                    stringResource(R.string.auth_dev_login_configuration),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
        state.serverUrl?.let { server ->
            Text(stringResource(R.string.auth_server_label, server), style = MaterialTheme.typography.bodySmall)
        }
        when (state.authenticationMode) {
            AuthenticationMode.BASIC -> {
                OutlinedTextField(value = username, onValueChange = {
                    username = it
                }, modifier = Modifier.fillMaxWidth(), label = { Text(stringResource(R.string.auth_username)) })
                OutlinedTextField(
                    value = password,
                    onValueChange = {
                        password = it
                    },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text(stringResource(R.string.auth_password)) },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    singleLine = true,
                )
                Button(
                    onClick = { onBasicLogin(username, password) },
                    enabled =
                        username.isNotBlank() && password.isNotBlank() && !state.isLoading,
                ) {
                    Text(stringResource(R.string.auth_sign_in))
                }
            }
            AuthenticationMode.OIDC ->
                Button(
                    onClick = onBeginOidc,
                    enabled = !state.isLoading,
                ) { Text(stringResource(R.string.auth_sign_in_browser)) }
            null -> Unit
        }
        if (state.isLoading) CircularProgressIndicator()
        state.error?.let { message ->
            Card {
                Text(
                    message,
                    modifier = Modifier.padding(OpenCloudDimensions.SpacingMd),
                    color = OpenCloudColor.Error,
                )
            }
        }
        state.session?.let { session ->
            SessionSummary(session)
        }
    }
}

@Composable
private fun SessionSummary(session: AuthenticatedSession) {
    Card {
        Column(
            modifier = Modifier.padding(OpenCloudDimensions.SpacingMd),
            verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingXxs),
        ) {
            Text(
                stringResource(R.string.auth_signed_in_as, session.profile.displayName),
                style = MaterialTheme.typography.titleMedium,
            )
            val version = session.capabilities.version ?: stringResource(R.string.auth_unknown)
            Text(stringResource(R.string.auth_server_version, version))
            val sharingStatus =
                if (session.capabilities.sharingEnabled) {
                    R.string.auth_sharing_available
                } else {
                    R.string.auth_sharing_unavailable
                }
            Text(stringResource(sharingStatus))
        }
    }
}

data class DevLoginConfiguration(
    val serverUrl: String,
    val username: String,
    val password: String,
) {
    val isConfigured: Boolean = serverUrl.isNotBlank() && username.isNotBlank() && password.isNotBlank()
}
