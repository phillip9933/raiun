package eu.opencloud.android.next.core.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.ProviderException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/** Provider boundary kept injectable so envelope and policy tests do not fake Android Keystore. */
internal interface VaultDeviceRememberCrypto {
    fun isPlatformSupported(): Boolean

    fun create(alias: String): SecretKey

    fun load(alias: String): SecretKey?

    fun aliases(): Set<String>

    fun delete(alias: String)

    fun isAcceptable(key: SecretKey): Boolean
}

internal class AndroidVaultDeviceRememberCrypto : VaultDeviceRememberCrypto {
    override fun isPlatformSupported(): Boolean = Build.VERSION.SDK_INT >= 35

    override fun create(alias: String): SecretKey {
        check(isPlatformSupported())
        require(alias.matches(Regex("raiun_vault_device_v1_[0-9a-f]{64}_[0-9a-f]{16}")))
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        check(!keyStore.containsAlias(alias)) { "Refusing to adopt an existing device-remember alias." }
        val spec =
            KeyGenParameterSpec
                .Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(KEY_SIZE_BITS)
                // Deliberately no setUserAuthenticationRequired/timeout. The device-unlocked
                // requirement is the documented Android 15+ policy for this alias namespace.
                .setUnlockedDeviceRequired(true)
                .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
            init(spec)
            generateKey()
        }
    }

    override fun load(alias: String): SecretKey? {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        return keyStore.getKey(alias, null) as? SecretKey
    }

    override fun aliases(): Set<String> =
        KeyStore
            .getInstance(ANDROID_KEY_STORE)
            .apply { load(null) }
            .aliases()
            .toList()
            .toSet()

    override fun delete(alias: String) {
        val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
        keyStore.deleteEntry(alias)
    }

    override fun isAcceptable(key: SecretKey): Boolean {
        val info = keyInfo(key) ?: return false
        return hasExactAesPolicy(key, info) && hasHardwareBacking(info) && unlockedRequirementAcceptable(info)
    }

    private fun keyInfo(key: SecretKey): KeyInfo? =
        try {
            SecretKeyFactory
                .getInstance(key.algorithm, ANDROID_KEY_STORE)
                .getKeySpec(key, KeyInfo::class.java) as? KeyInfo
        } catch (_: GeneralSecurityException) {
            null
        } catch (_: IllegalStateException) {
            null
        } catch (_: IllegalArgumentException) {
            null
        } catch (_: SecurityException) {
            null
        } catch (_: ProviderException) {
            null
        }

    private fun hasExactAesPolicy(
        key: SecretKey,
        info: KeyInfo,
    ): Boolean =
        key.algorithm.equals(KeyProperties.KEY_ALGORITHM_AES, ignoreCase = true) &&
            info.keySize == KEY_SIZE_BITS &&
            info.purposes == (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) &&
            info.blockModes.contentEquals(arrayOf(KeyProperties.BLOCK_MODE_GCM)) &&
            info.encryptionPaddings.contentEquals(arrayOf(KeyProperties.ENCRYPTION_PADDING_NONE)) &&
            info.origin == KeyProperties.ORIGIN_GENERATED &&
            !info.isUserAuthenticationRequired

    private fun hasHardwareBacking(info: KeyInfo): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }

    private fun unlockedRequirementAcceptable(info: KeyInfo): Boolean =
        when (val getter = unlockedRequirementGetter(info)) {
            UnlockedGetter.MISSING -> true // API 35 has no public getter; trust its documented creation contract.
            UnlockedGetter.REJECTED -> false
            is UnlockedGetter.VALUE -> getter.value
        }

    private fun unlockedRequirementGetter(info: KeyInfo): UnlockedGetter =
        try {
            val method = KeyInfo::class.java.getMethod("isUnlockedDeviceRequired")
            val value = method.invoke(info) as? Boolean ?: return UnlockedGetter.REJECTED
            UnlockedGetter.VALUE(value)
        } catch (_: NoSuchMethodException) {
            UnlockedGetter.MISSING
        } catch (_: ReflectiveOperationException) {
            UnlockedGetter.REJECTED
        } catch (_: SecurityException) {
            UnlockedGetter.REJECTED
        }

    private sealed interface UnlockedGetter {
        data object MISSING : UnlockedGetter

        data object REJECTED : UnlockedGetter

        data class VALUE(
            val value: Boolean,
        ) : UnlockedGetter
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val KEY_SIZE_BITS = 256
    }
}

internal class VaultDeviceRememberUnavailableException(
    cause: Throwable? = null,
) : GeneralSecurityException("Device remember protection is unavailable.", cause)
