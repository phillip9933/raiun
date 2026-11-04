package eu.opencloud.android.next.core.security

import android.content.Context
import android.util.Base64
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.ClientRegistrationSource
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey

/** Real AndroidKeyStore, synthetic task-app credentials only; no network or device authentication. */
@RunWith(AndroidJUnit4::class)
class CredentialSlotBindingAndroidTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val preferences = context.getSharedPreferences("secure_credentials", Context.MODE_PRIVATE)
    private val store get() = KeystoreCredentialStore(context)
    private val account = "slot-native-${UUID.randomUUID()}"
    private val other = "slot-native-${UUID.randomUUID()}"
    private val tokens = AuthTokens("synthetic-access", "synthetic-refresh", 1, "bearer", "openid")

    @Test fun productionWritesBindBasicTokensAndRegistrationToFullSlots() =
        withCleanup {
            store.saveBasicCredentials(account, "synthetic-user", "synthetic-password")
            store.saveRegisteredTokens(
                account,
                tokens,
                OidcClientRegistration(
                    "https://cloud.invalid",
                    "https://issuer.invalid",
                    "client",
                    "app.raiun.cloud://oauth",
                    "https://issuer.invalid/auth",
                    "https://issuer.invalid/token",
                    ClientRegistrationSource.STATIC,
                ),
            )
            val slots = listOf("basic.username.$account", "basic.$account", "tokens.$account", "oidc.account:$account")
            val codec =
                CredentialCipher { create ->
                    assertFalse(create)
                    originalKey()
                }
            slots.forEach { slot ->
                val encoded = requireNotNull(preferences.getString(slot, null))
                assertTrue(encoded.startsWith("v2:"))
                assertFalse(requireNotNull(codec.decrypt(slot, encoded)).legacy)
                slots.filter { it != slot }.forEach { assertNull(codec.decrypt(it, encoded)) }
            }
            preferences.edit().putString("tokens.$other", preferences.getString("tokens.$account", null)).commit()
            assertNull(store.readTokens(other))
            assertEquals(tokens, store.readTokens(account))
            assertEquals("synthetic-password", store.readBasicPassword(account))
        }

    @Test fun originalAliasLegacyCiphertextMigratesAndReopensWithoutReplacingKey() =
        withCleanup {
            store.saveTokens(account, tokens) // Creates the original alias using the production path.
            val key = originalKey()
            val legacy = legacy(key, "synthetic-access\u0000synthetic-refresh\u00001\u0000bearer\u0000openid")
            check(preferences.edit().putString("tokens.$account", legacy).commit())
            assertEquals(tokens, store.readTokens(account))
            val migrated = requireNotNull(preferences.getString("tokens.$account", null))
            assertTrue(migrated.startsWith("v2:"))
            val codec =
                CredentialCipher { create ->
                    assertFalse(create)
                    key
                }
            assertFalse(requireNotNull(codec.decrypt("tokens.$account", migrated)).legacy)
            assertEquals(tokens, store.readTokens(account))
            assertNull(codec.decrypt("tokens.$other", migrated))
        }

    @Test fun realProviderRejectsCorruptLegacyAndSemanticallyInvalidAuthenticatedData() =
        withCleanup {
            store.saveTokens(account, tokens)
            val invalid = legacy(originalKey(), "access\u0000refresh\u0000not-a-time\u0000Bearer\u0000openid")
            check(preferences.edit().putString("tokens.$account", invalid).commit())
            assertNull(store.readTokens(account))
            assertEquals(invalid, preferences.getString("tokens.$account", null))
            val parts = invalid.split(':')
            val bytes = Base64.decode(parts[1], Base64.NO_WRAP)
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            val corrupt = "${parts[0]}:${Base64.encodeToString(bytes, Base64.NO_WRAP)}"
            check(preferences.edit().putString("tokens.$account", corrupt).commit())
            assertNull(store.readTokens(account))
            assertEquals(corrupt, preferences.getString("tokens.$account", null))
        }

    private fun originalKey(): SecretKey =
        KeyStore.getInstance("AndroidKeyStore").run {
            load(null)
            requireNotNull(getKey(CREDENTIAL_KEY_ALIAS, null) as? SecretKey)
        }

    private fun legacy(
        key: SecretKey,
        value: String,
    ): String =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, key)
            listOf(
                iv,
                doFinal(value.toByteArray(Charsets.UTF_8)),
            ).joinToString(":") { Base64.encodeToString(it, Base64.NO_WRAP) }
        }

    private fun withCleanup(action: () -> Unit) {
        try {
            action()
        } finally {
            store.remove(account)
            store.remove(other)
        }
    }
}
