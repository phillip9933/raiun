package eu.opencloud.android.next.core.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import org.json.JSONArray
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

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

class KeystoreCredentialStore internal constructor(
    context: Context,
    private val preferences: SharedPreferences,
    private val cipher: CredentialCipher,
) : CredentialStore {
    private val context = context.applicationContext
    constructor(context: Context) : this(
        context,
        context.applicationContext.getSharedPreferences("secure_credentials", Context.MODE_PRIVATE),
        CredentialCipher(::credentialSecretKey),
    )

    override fun saveBasicCredentials(
        accountId: String,
        username: String,
        password: String,
    ) {
        VaultUnlockSession.forgetProcessAccount(accountId)
        try {
            VaultDeviceRememberStore(context).revokeAccountAnd(accountId) {
                synchronized(credentialLock) {
                    persistBasicCredentials(
                        preferences,
                        accountId,
                        username,
                        password,
                    ) { slot, value -> cipher.encrypt(slot, value) }
                }
            }
        } finally {
            VaultUnlockSession.forgetProcessAccount(accountId)
        }
    }

    fun savePendingLogin(login: PendingOidcLogin) =
        synchronized(credentialLock) {
            val serialized = login.encode()
            requireNotNull(CredentialRecords.pending(serialized))
            check(preferences.edit().putString(PENDING_SLOT, cipher.encrypt(PENDING_SLOT, serialized)).commit())
        }

    fun consumePendingLogin(
        state: String,
        now: Long,
    ): PendingOidcLogin? =
        synchronized(credentialLock) {
            val encoded = encoded(PENDING_SLOT) ?: return@synchronized null
            val decoded = cipher.decrypt(PENDING_SLOT, encoded) ?: return@synchronized null
            val pending = CredentialRecords.pending(decoded.plaintext) ?: return@synchronized null
            if (!pending.validAt(now)) {
                check(preferences.edit().remove(PENDING_SLOT).commit())
                return@synchronized null
            }
            if (pending.request.state != state) {
                migrate(PENDING_SLOT, decoded)
                return@synchronized null
            }
            check(preferences.edit().remove(PENDING_SLOT).commit())
            pending
        }

    override fun saveBasicUsername(
        accountId: String,
        username: String,
    ) {
        VaultUnlockSession.forgetProcessAccount(accountId)
        try {
            VaultDeviceRememberStore(context).revokeAccountAnd(accountId) {
                synchronized(credentialLock) {
                    write("basic.username.$accountId", username, CredentialRecords::basic)
                }
            }
        } finally {
            VaultUnlockSession.forgetProcessAccount(accountId)
        }
    }

    override fun readBasicUsername(accountId: String): String? =
        read("basic.username.$accountId", CredentialRecords::basic)

    override fun saveBasicPassword(
        accountId: String,
        password: String,
    ) {
        VaultUnlockSession.forgetProcessAccount(accountId)
        try {
            VaultDeviceRememberStore(context).revokeAccountAnd(accountId) {
                synchronized(credentialLock) {
                    write("basic.$accountId", password, CredentialRecords::basic)
                }
            }
        } finally {
            VaultUnlockSession.forgetProcessAccount(accountId)
        }
    }

    override fun readBasicPassword(accountId: String): String? = read("basic.$accountId", CredentialRecords::basic)

    override fun saveTokens(
        accountId: String,
        tokens: AuthTokens,
    ) {
        synchronized(credentialLock) {
            write("tokens.$accountId", serializeTokens(tokens), CredentialRecords::tokens)
        }
    }

    override fun readTokens(accountId: String): AuthTokens? = read("tokens.$accountId", CredentialRecords::tokens)

    override fun readClientRegistration(key: String): OidcClientRegistration? =
        read("oidc.$key", CredentialRecords::registration)

    override fun invalidateClientRegistration(registration: OidcClientRegistration) =
        synchronized(credentialLock) {
            val editor = preferences.edit()
            preferences.all.keys.filter { it.startsWith("oidc.") }.forEach { key ->
                val candidate =
                    encoded(
                        key,
                    )?.let { cipher.decrypt(key, it) }?.let { CredentialRecords.registration(it.plaintext) }
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
        synchronized(credentialLock) {
            write("oidc.$key", serializeRegistration(registration), CredentialRecords::registration)
        }
    }

    override fun saveRegisteredTokens(
        accountId: String,
        tokens: AuthTokens,
        registration: OidcClientRegistration,
    ) {
        VaultUnlockSession.forgetProcessAccount(accountId)
        try {
            VaultDeviceRememberStore(context).revokeAccountAnd(accountId) {
                synchronized(credentialLock) {
                    val serializedTokens = serializeTokens(tokens)
                    val serializedRegistration = serializeRegistration(registration)
                    requireNotNull(CredentialRecords.tokens(serializedTokens))
                    requireNotNull(CredentialRecords.registration(serializedRegistration))
                    check(
                        preferences
                            .edit()
                            .putString("tokens.$accountId", cipher.encrypt("tokens.$accountId", serializedTokens))
                            .putString(
                                "oidc.account:$accountId",
                                cipher.encrypt("oidc.account:$accountId", serializedRegistration),
                            ).commit(),
                    ) { "The session could not be persisted." }
                }
            }
        } finally {
            VaultUnlockSession.forgetProcessAccount(accountId)
        }
    }

    override fun remove(accountId: String) {
        VaultUnlockSession.forgetProcessAccount(accountId)
        try {
            VaultDeviceRememberStore(context).revokeAccountAnd(accountId) {
                synchronized(credentialLock) {
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
            }
        } finally {
            VaultUnlockSession.forgetProcessAccount(accountId)
        }
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

    private fun encoded(slot: String): String? = preferences.all[slot] as? String

    private fun <T : Any> read(
        slot: String,
        validate: (String) -> T?,
    ): T? =
        synchronized(credentialLock) {
            val encoded = encoded(slot) ?: return@synchronized null
            val decoded = cipher.decrypt(slot, encoded) ?: return@synchronized null
            val record = validate(decoded.plaintext) ?: return@synchronized null
            if (!migrate(slot, decoded)) return@synchronized null
            record
        }

    private fun <T : Any> write(
        slot: String,
        value: String,
        validate: (String) -> T?,
    ) {
        requireNotNull(validate(value)) { "Invalid credential record." }
        check(preferences.edit().putString(slot, cipher.encrypt(slot, value)).commit()) {
            "Credentials could not be persisted."
        }
    }

    // Caller holds credentialLock, from the original read through the checked replacement.
    // Never calls vault revocation: migration changes only the envelope, not the credential.
    @Suppress("TooGenericExceptionCaught")
    private fun migrate(
        slot: String,
        decoded: CredentialPlaintext,
    ): Boolean {
        if (!decoded.legacy) return true
        return try {
            check(
                preferences
                    .edit()
                    .putString(
                        slot,
                        cipher.encrypt(slot, decoded.plaintext, createIfMissing = false),
                    ).commit(),
            )
            true
        } catch (_: Exception) {
            Log.w("CredentialStore", "Credential unavailable: migration_failed")
            false
        }
    }

    private companion object {
        // Lock order: vault revocation ledger -> credential state -> key initialization.
        // No operation under this lock may acquire the vault ledger. Shared across store instances.
        val credentialLock = Any()
        const val PENDING_SLOT = "pending.oidc"
    }
}

internal fun persistBasicCredentials(
    preferences: SharedPreferences,
    accountId: String,
    username: String,
    password: String,
    encrypt: (String, String) -> String,
) {
    require(
        accountId.isNotBlank() &&
            CredentialRecords.basic(
                username,
            ) != null &&
            CredentialRecords.basic(password) != null,
    ) {
        "Basic credentials are incomplete."
    }
    val encryptedUsername = encrypt("basic.username.$accountId", username)
    val encryptedPassword = encrypt("basic.$accountId", password)
    check(
        preferences
            .edit()
            .putString("basic.username.$accountId", encryptedUsername)
            .putString("basic.$accountId", encryptedPassword)
            .commit(),
    ) { "Credentials could not be persisted." }
}

private fun credentialSecretKey(createIfMissing: Boolean): SecretKey? =
    CredentialKeyInitialization.obtain(
        createIfMissing = createIfMissing,
        lookup = {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (keyStore.containsAlias(CREDENTIAL_KEY_ALIAS)) {
                checkNotNull(
                    keyStore.getKey(CREDENTIAL_KEY_ALIAS, null) as? SecretKey,
                ) { "Credential key unavailable." }
            } else {
                null
            }
        },
        create = {
            KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply {
                    init(
                        KeyGenParameterSpec
                            .Builder(
                                CREDENTIAL_KEY_ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                            ).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .build(),
                    )
                }.generateKey()
        },
    )

internal const val CREDENTIAL_KEY_ALIAS = "opencloud.next.credentials.v1"

/** One process-wide lock covers lookup and creation across store instances. Reads never create keys. */
internal object CredentialKeyInitialization {
    @Synchronized
    fun <T : Any> obtain(
        createIfMissing: Boolean,
        lookup: () -> T?,
        create: () -> T,
    ): T? = lookup() ?: if (createIfMissing) create() else null
}

internal fun credentialFailureCategory(error: Exception): String =
    when (error) {
        is javax.crypto.AEADBadTagException -> "authentication_failed"
        is IllegalArgumentException -> "invalid_envelope"
        else -> "key_or_crypto_unavailable"
    }
