package eu.opencloud.android.next

import android.app.Activity
import android.app.KeyguardManager
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import eu.opencloud.android.next.core.security.AppLock

/** Only a successful system authentication can issue an in-memory unlock grant. */
class DeviceUnlockActivity : AppCompatActivity() {
    private val credentials =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            if (it.resultCode == Activity.RESULT_OK) authenticated() else finish()
        }

    override fun onResume() {
        super.onResume()
        restoreStoredTaskAppearance()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        applyStoredWindowTheme()
        super.onCreate(savedInstanceState)
        restoreStoredTaskAppearance()
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val lock = AppLock(this)
        if (!lock.deviceSecure) {
            finish()
            return
        }
        // Reattach the callback after rotation; AndroidX retains the active prompt.
        val prompt =
            BiometricPrompt(
                this,
                ContextCompat.getMainExecutor(this),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) =
                        authenticated()

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence,
                    ) {
                        if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON) showCredentials() else finish()
                    }
                },
            )
        if (savedInstanceState != null) return
        if (lock.biometricEnabled && lock.biometricAvailable) {
            val builder =
                BiometricPrompt.PromptInfo
                    .Builder()
                    .setTitle(getString(R.string.app_lock_unlock_biometric))
                    .setSubtitle(getString(R.string.app_lock_biometric_subtitle))
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            } else {
                builder
                    .setAllowedAuthenticators(BIOMETRIC_STRONG)
                    .setNegativeButtonText(getString(R.string.app_lock_use_device_credentials))
            }
            prompt.authenticate(builder.build())
        } else {
            showCredentials()
        }
    }

    private fun showCredentials() {
        @Suppress("DEPRECATION")
        val intent =
            getSystemService(KeyguardManager::class.java)
                .createConfirmDeviceCredentialIntent(
                    getString(R.string.app_lock_unlock_biometric),
                    getString(R.string.app_lock_confirm_credentials),
                )
        if (intent == null) finish() else credentials.launch(intent)
    }

    private fun authenticated() {
        val lock = AppLock(this)
        lock.authenticated()
        when (intent.action) {
            "enable-lock" -> lock.setEnabled(true)
            "disable-lock" -> lock.setEnabled(false)
        }
        lock.notifyProvider()
        setResult(Activity.RESULT_OK)
        finish()
    }
}
