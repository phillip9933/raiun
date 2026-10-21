package eu.opencloud.android.next.core.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.ClientRegistrationSource
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import org.json.JSONArray
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

interface CredentialStore {
    fun saveBasicCredentials(
        accountId: String,
        username: String,
        password: String,
    ): Unit = error("Atomic basic credential persistence is unavailable.")

    fun saveBasicUsername(
        accountId: String,
        username: String,
    )

    fun readBasicUsername(accountId: String): String?

    fun saveBasicPassword(
        accountId: String,
        password: String,
    )

    fun readBasicPassword(accountId: String): String?

    fun saveTokens(
        accountId: String,
        tokens: AuthTokens,
    )

    fun readTokens(accountId: String): AuthTokens?

    fun remove(accountId: String)

    fun readClientRegistration(key: String): OidcClientRegistration? = null

    fun invalidateClientRegistration(registration: OidcClientRegistration): Unit =
        error("Client registration persistence is unavailable.")

    fun saveClientRegistration(
        key: String,
        registration: OidcClientRegistration,
    ): Unit = error("Client registration persistence is unavailable.")

    fun saveRegisteredTokens(
        accountId: String,
        tokens: AuthTokens,
        registration: OidcClientRegistration,
    ): Unit = error("Atomic session persistence is unavailable.")
}

class KeystoreCredentialStore(
    context: Context,
) : CredentialStore {
    private val preferences = context.getSharedPreferences("secure_credentials", Context.MODE_PRIVATE)

    override fun saveBasicCredentials(
        accountId: String,
        username: String,
        password: String,
    ) = persistBasicCredentials(preferences, accountId, username, password, ::encrypt)

    fun savePendingLogin(login: PendingOidcLogin) =
        synchronized(pendingLoginLock) {
            check(preferences.edit().putString("pending.oidc", encrypt(login.encode())).commit())
        }

    fun consumePendingLogin(
        state: String,
        now: Long,
    ): PendingOidcLogin? =
        synchronized(pendingLoginLock) {
            val encoded = preferences.getString("pending.oidc", null) ?: return@synchronized null
            val pending = PendingOidcLogin.decode(requireNotNull(decrypt(encoded)))
            if (!pending.validAt(now)) {
                check(preferences.edit().remove("pending.oidc").commit())
                return@synchronized null
            }
            if (pending.request.state != state) return@synchronized null
            check(preferences.edit().remove("pending.oidc").commit())
            pending
        }

    override fun saveBasicUsername(
        accountId: String,
        username: String,
    ) {
        preferences.edit().putString("basic.username.$accountId", encrypt(username)).apply()
    }

    override fun readBasicUsername(accountId: String): String? =
        preferences.getString("basic.username.$accountId", null)?.let(::decrypt)

    override fun saveBasicPassword(
        accountId: String,
        password: String,
    ) {
        preferences.edit().putString("basic.$accountId", encrypt(password)).apply()
    }

    override fun readBasicPassword(accountId: String): String? =
        preferences.getString("basic.$accountId", null)?.let(::decrypt)

    override fun saveTokens(
        accountId: String,
        tokens: AuthTokens,
    ) {
        val serialized = serializeTokens(tokens)
        check(preferences.edit().putString("tokens.$accountId", encrypt(serialized)).commit()) {
            "Credentials could not be persisted."
        }
    }

    override fun readTokens(accountId: String): AuthTokens? =
        preferences
            .getString("tokens.$accountId", null)
            ?.let(::decrypt)
            ?.split("\u0000")
            ?.takeIf { it.size == 5 }
            ?.let { values ->
                AuthTokens(
                    accessToken = values[0],
                    refreshToken = values[1].ifBlank { null },
                    expiresAtEpochSeconds = values[2].toLongOrNull() ?: return null,
                    tokenType = values[3],
                    scope = values[4].ifBlank { null },
                )
            }

    override fun readClientRegistration(key: String): OidcClientRegistration? =
        preferences.getString("oidc.$key", null)?.let(::decrypt)?.let { serialized ->
            runCatching {
                val values = JSONArray(serialized)
                OidcClientRegistration(
                    values.getString(0),
                    values.getString(1),
                    values.getString(2),
                    values.getString(3),
                    values.getString(4),
                    values.getString(5),
                    ClientRegistrationSource.valueOf(values.getString(6)),
                    values.getString(7).ifBlank { null },
                    values.getString(8).ifBlank { null },
                )
            }.getOrNull()
        }

    override fun invalidateClientRegistration(registration: OidcClientRegistration) {
        val editor = preferences.edit()
        preferences.all.keys.filter { it.startsWith("oidc.") }.forEach { key ->
            val candidate = readClientRegistration(key.removePrefix("oidc."))
            if (candidate?.serverUrl == registration.serverUrl &&
                candidate.issuer == registration.issuer &&
                candidate.clientId == registration.clientId
            ) {
                editor.remove(key)
            }
        }
        check(editor.commit()) { "Client registration could not be invalidated." }
    }

    override fun saveClientRegistration(
        key: String,
        registration: OidcClientRegistration,
    ) {
        check(preferences.edit().putString("oidc.$key", encrypt(serializeRegistration(registration))).commit()) {
            "Client registration could not be persisted."
        }
    }

    override fun saveRegisteredTokens(
        accountId: String,
        tokens: AuthTokens,
        registration: OidcClientRegistration,
    ) {
        check(
            preferences
                .edit()
                .putString("tokens.$accountId", encrypt(serializeTokens(tokens)))
                .putString("oidc.account:$accountId", encrypt(serializeRegistration(registration)))
                .commit(),
        ) { "The session could not be persisted." }
    }

    override fun remove(accountId: String) {
        check(
            preferences
                .edit()
                .remove("basic.username.$accountId")
                .remove("basic.$accountId")
                .remove("tokens.$accountId")
                .remove("oidc.account:$accountId")
                .commit(),
        ) { "Credentials could not be removed." }
    }

    private fun serializeTokens(tokens: AuthTokens): String =
        listOf(
            tokens.accessToken,
            tokens.refreshToken.orEmpty(),
            tokens.expiresAtEpochSeconds.toString(),
            tokens.tokenType,
            tokens.scope.orEmpty(),
        ).joinToString("\u0000")

    private fun serializeRegistration(registration: OidcClientRegistration): String =
        JSONArray(
            listOf(
                registration.serverUrl,
                registration.issuer,
                registration.clientId,
                registration.redirectUri,
                registration.authorizationEndpoint,
                registration.tokenEndpoint,
                registration.source.name,
                registration.registrationAccessToken.orEmpty(),
                registration.registrationClientUri.orEmpty(),
            ),
        ).toString()

    private fun encrypt(value: String): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey())
        val encrypted = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
        return listOf(cipher.iv, encrypted).joinToString(":") { Base64.encodeToString(it, Base64.NO_WRAP) }
    }

    private fun decrypt(value: String): String? =
        runCatching {
            val (iv, encrypted) = value.split(":", limit = 2).map { Base64.decode(it, Base64.NO_WRAP) }
            Cipher.getInstance(TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
                String(doFinal(encrypted), StandardCharsets.UTF_8)
            }
        }.getOrNull()

    private fun secretKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return (keyStore.getKey(KEY_ALIAS, null) as? SecretKey) ?: KeyGenerator
            .getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE,
            ).apply {
                init(
                    KeyGenParameterSpec
                        .Builder(
                            KEY_ALIAS,
                            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                        ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .build(),
                )
            }.generateKey()
    }

    private companion object {
        val pendingLoginLock = Any()
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "opencloud.next.credentials.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_LENGTH_BITS = 128
    }
}

internal fun persistBasicCredentials(
    preferences: android.content.SharedPreferences,
    accountId: String,
    username: String,
    password: String,
    encrypt: (String) -> String,
) {
    require(accountId.isNotBlank() && username.isNotBlank() && password.isNotBlank()) {
        "Basic credentials are incomplete."
    }
    val encryptedUsername = encrypt(username)
    val encryptedPassword = encrypt(password)
    check(
        preferences
            .edit()
            .putString("basic.username.$accountId", encryptedUsername)
            .putString("basic.$accountId", encryptedPassword)
            .commit(),
    ) { "Credentials could not be persisted." }
}
