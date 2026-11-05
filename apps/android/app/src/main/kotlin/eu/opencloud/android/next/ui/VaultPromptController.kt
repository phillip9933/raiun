package eu.opencloud.android.next.ui

import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import eu.opencloud.android.next.R
import javax.crypto.Cipher

internal class VaultPromptController(
    private val activity: ComponentActivity,
    private val viewModel: VaultViewModel,
) {
    private var activePrompt: BiometricPrompt? = null
    private var cancelPending: (() -> Unit)? = null
    private var generation = 0L

    fun cancel() {
        generation += 1
        val prompt = activePrompt
        val cancelOperation = cancelPending
        activePrompt = null
        cancelPending = null
        runCatching { prompt?.cancelAuthentication() }
        cancelOperation?.invoke()
    }

    fun showUnlock(title: String) {
        cancel()
        if (!hardwareAvailable()) return unavailable()
        val cipher = viewModel.prepareBiometricUnlock() ?: return
        startPrompt(title, cipher, viewModel::cancelBiometricUnlock, viewModel::completeBiometricUnlock, false)
    }

    fun showEnrollment(title: String) {
        cancel()
        if (!hardwareAvailable()) return unavailable()
        val cipher = viewModel.prepareBiometricEnrollment() ?: return
        startPrompt(title, cipher, viewModel::cancelBiometricEnrollment, viewModel::completeBiometricEnrollment)
    }

    private fun startPrompt(
        title: String,
        cipher: Cipher,
        cancelOperation: () -> Unit,
        complete: (Cipher?) -> Unit,
        confirmationRequired: Boolean = true,
    ) {
        cancelPending = cancelOperation
        val requestGeneration = ++generation
        try {
            val prompt =
                biometricPrompt(
                    activity,
                    { result ->
                        if (generation == requestGeneration) {
                            generation += 1
                            activePrompt = null
                            cancelPending = null
                            complete(result.cryptoObject?.cipher)
                        }
                    },
                    {
                        if (generation == requestGeneration) {
                            generation += 1
                            activePrompt = null
                            cancelPending = null
                            cancelOperation()
                        }
                    },
                )
            activePrompt = prompt
            prompt.authenticate(
                biometricPromptInfo(
                    title = activity.getString(R.string.vault_biometric_title, title),
                    subtitle = activity.getString(R.string.vault_biometric_subtitle),
                    negativeButton = activity.getString(R.string.vault_biometric_cancel),
                    confirmationRequired = confirmationRequired,
                ),
                BiometricPrompt.CryptoObject(cipher),
            )
        } catch (_: RuntimeException) {
            if (generation == requestGeneration) {
                cancel()
                unavailable()
            }
        }
    }

    private fun hardwareAvailable(): Boolean =
        runCatching {
            BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
        }.getOrDefault(false)

    private fun unavailable() {
        Toast.makeText(activity, R.string.vault_biometric_unavailable, Toast.LENGTH_SHORT).show()
    }
}

private fun biometricPrompt(
    activity: ComponentActivity,
    onSuccess: (BiometricPrompt.AuthenticationResult) -> Unit,
    onError: () -> Unit,
): BiometricPrompt =
    BiometricPrompt(
        activity as androidx.fragment.app.FragmentActivity,
        ContextCompat.getMainExecutor(activity),
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) = onSuccess(result)

            override fun onAuthenticationError(
                errorCode: Int,
                errString: CharSequence,
            ) = onError()
        },
    )

internal fun biometricPromptInfo(
    title: String,
    subtitle: String,
    negativeButton: String,
    confirmationRequired: Boolean = true,
): BiometricPrompt.PromptInfo =
    BiometricPrompt.PromptInfo
        .Builder()
        .setTitle(title)
        .setSubtitle(subtitle)
        .setNegativeButtonText(negativeButton)
        .setConfirmationRequired(confirmationRequired)
        .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
        .build()
