package eu.opencloud.android.next.feature.auth

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
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
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions

@Composable
internal fun AppTokenFields(
    server: String,
    loading: Boolean,
    error: String?,
    login: (String, String, String) -> Unit,
) {
    var username by rememberSaveable { mutableStateOf("") }
    var token by remember { mutableStateOf("") }
    Column(verticalArrangement = Arrangement.spacedBy(OpenCloudDimensions.SpacingSm)) {
        Text(stringResource(R.string.auth_app_token_description))
        OutlinedTextField(
            username,
            { username = it },
            Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.auth_username)) },
            singleLine = true,
        )
        OutlinedTextField(
            token,
            { token = it },
            Modifier.fillMaxWidth(),
            label = { Text(stringResource(R.string.auth_app_password_or_token)) },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        )
        Button(
            onClick = { login(server, username, token) },
            enabled = !loading && server.isNotBlank() && username.isNotBlank() && token.isNotBlank(),
        ) { Text(stringResource(R.string.auth_sign_in)) }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
    }
}
