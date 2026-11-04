package eu.opencloud.android.next.core.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.ClientRegistrationSource
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import eu.opencloud.android.next.core.model.auth.OidcConfiguration
import eu.opencloud.android.next.core.model.auth.PkceRequest
import org.json.JSONArray
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.lang.reflect.Proxy
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
class CredentialSlotBindingTest {
    private val context: Context = RuntimeEnvironment.getApplication()
    private val preferences = context.getSharedPreferences("credential-${UUID.randomUUID()}", Context.MODE_PRIVATE)
    private val key = SecretKeySpec(ByteArray(32) { it.toByte() }, "AES")
    private val cipher = CredentialCipher { key }
    private val store get() = KeystoreCredentialStore(context, preferences, cipher)
    private val tokens = AuthTokens("access", "refresh", -1, "bearer", "openid offline_access")
    private val registration =
        OidcClientRegistration(
            "https://cloud.example",
            "https://id.example",
            "client",
            "app.raiun.cloud://oauth",
            "https://id.example/auth",
            "https://id.example/token",
            ClientRegistrationSource.DYNAMIC,
            "management-token",
            "https://id.example/registration",
        )
    private val pending =
        PendingOidcLogin(
            "https://cloud.example",
            OidcConfiguration(
                "https://id.example",
                "https://id.example/auth",
                "https://id.example/token",
                null,
                "client",
                listOf("openid"),
            ),
            PkceRequest("https://id.example/auth?state=state", "state", "a".repeat(43)),
            1_000,
        )

    @Test fun everyWrittenKindUsesV2AndExactSlotBinding() {
        store.saveBasicCredentials("account", "alice", "secret")
        store.saveRegisteredTokens("account", tokens, registration)
        store.saveClientRegistration("cache-key", registration)
        store.savePendingLogin(pending)
        assertEquals(6, preferences.all.size)
        preferences.all.forEach { (slot, value) ->
            assertTrue((value as String).startsWith("v2:"))
            assertFalse(requireNotNull(cipher.decrypt(slot, value)).legacy)
            assertNull(cipher.decrypt("$slot.other", value))
        }
        assertEquals("alice", store.readBasicUsername("account"))
        assertEquals("secret", store.readBasicPassword("account"))
        assertEquals(tokens, store.readTokens("account"))
        assertEquals(registration, store.readClientRegistration("account:account"))
    }

    @Test fun maximumUnicodeCredentialRoundTripsAndMalformedUnicodeNeverWrites() {
        val password = "界".repeat(64 * 1024)
        store.saveBasicPassword("a", password)
        assertEquals(password, store.readBasicPassword("a"))
        val previous = preferences.getString("basic.a", null)
        val failure =
            assertThrows(VaultDeviceRememberException::class.java) {
                store.saveBasicPassword("a", "\ud800")
            }
        assertTrue(failure.cause is java.nio.charset.CharacterCodingException)
        assertEquals(previous, preferences.getString("basic.a", null))
        assertThrows(java.nio.charset.CharacterCodingException::class.java) { cipher.encrypt("bad\ud800", "valid") }
    }

    @Test fun everyCiphertextRejectsEveryOtherKindAndAccountSlot() {
        val slots =
            listOf(
                "basic.username.a",
                "basic.a",
                "tokens.a",
                "oidc.account:a",
                "pending.oidc",
                "tokens.b",
                "oidc.cache",
            )
        slots.forEach { source ->
            val encrypted = cipher.encrypt(source, "synthetic")
            slots.filter { it != source }.forEach { destination -> assertNull(cipher.decrypt(destination, encrypted)) }
        }
        store.saveTokens("a", tokens)
        preferences.edit().putString("tokens.b", preferences.getString("tokens.a", null)).commit()
        assertNull(store.readTokens("b"))
        preferences.edit().putString("basic.a", preferences.getString("tokens.a", null)).commit()
        assertNull(store.readBasicPassword("a"))
    }

    @Test fun legacyRecordsMigrateOnlyAfterTypedValidationAndSurviveStoreRecreation() {
        putLegacy("basic.username.a", "alice")
        putLegacy("basic.a", "password")
        putLegacy("tokens.a", listOf("access", "refresh", "-1", "bearer", "openid").joinToString("\u0000"))
        putLegacy("oidc.account:a", registrationJson())
        assertEquals("alice", store.readBasicUsername("a"))
        assertEquals("password", store.readBasicPassword("a"))
        assertEquals(tokens.copy(scope = "openid"), store.readTokens("a"))
        assertEquals(registration, store.readClientRegistration("account:a"))
        preferences.all.forEach { (slot, value) ->
            assertTrue((value as String).startsWith("v2:"))
            assertFalse(requireNotNull(cipher.decrypt(slot, value)).legacy)
        }
        assertEquals("password", store.readBasicPassword("a"))
    }

    @Test fun malformedAuthenticatedLegacyRecordsNeverMigrate() {
        val cases =
            listOf(
                "basic.a" to "",
                "basic.username.a" to "\u0000",
                "tokens.a" to "access\u0000refresh\u0000not-a-time\u0000Bearer\u0000openid",
                "tokens.a" to "\u0000\u00001\u0000Bearer\u0000",
                "tokens.a" to "bad:token\u0000refresh\u00001\u0000Bearer\u0000openid",
                "tokens.a" to "bad\"token\u0000refresh\u00001\u0000Bearer\u0000openid",
                "tokens.a" to "access\u0000refresh\u00001\u0000Digest\u0000openid",
                "tokens.a" to "access\u0000refresh\u00001\u0000Bearer\u0000openid  profile",
                "tokens.a" to "access\u0000refresh\u00001\u0000Bearer\u0000openid\\profile",
                "oidc.a" to JSONArray(registrationJson()).put(2, 42).toString(),
                "oidc.a" to JSONArray(registrationJson()).put(2, "client\nvalue").toString(),
                "oidc.a" to JSONArray(registrationJson()).put(3, "https://unexpected.example").toString(),
                "oidc.a" to JSONArray(registrationJson()).put("extra").toString(),
                "pending.oidc" to "[invalid",
                "pending.oidc" to JSONArray(pending.encode()).put(10, "1000").toString(),
            )
        cases.forEach { (slot, value) ->
            val encrypted = putLegacy(slot, value)
            when {
                slot == "basic.a" -> assertNull(store.readBasicPassword("a"))
                slot.startsWith("basic.username") -> assertNull(store.readBasicUsername("a"))
                slot.startsWith("tokens") -> assertNull(store.readTokens("a"))
                slot.startsWith("oidc") -> assertNull(store.readClientRegistration("a"))
                else -> assertNull(store.consumePendingLogin("state", 1_001))
            }
            assertEquals(encrypted, preferences.getString(slot, null))
        }
    }

    @Test fun invalidationDeletesMatchingLegacyDirectlyWithoutMigrationWrite() {
        putLegacy("oidc.account:a", registrationJson())
        putLegacy("oidc.cache", registrationJson())
        val unrelated = registration.copy(clientId = "other-client")
        store.saveClientRegistration("unrelated", unrelated)
        val commits = AtomicInteger()
        val subject =
            KeystoreCredentialStore(
                context,
                wrapPreferences {
                    commits.incrementAndGet()
                    true
                },
                cipher,
            )
        subject.invalidateClientRegistration(registration)
        assertEquals(1, commits.get())
        assertFalse(preferences.contains("oidc.account:a"))
        assertFalse(preferences.contains("oidc.cache"))
        assertEquals(unrelated, store.readClientRegistration("unrelated"))
    }

    @Test fun invalidationFailureIsReportedRatherThanReturningSuccessfulMigration() {
        putLegacy("oidc.account:a", registrationJson())
        val subject = KeystoreCredentialStore(context, wrapPreferences { false }, cipher)
        assertThrows(IllegalStateException::class.java) { subject.invalidateClientRegistration(registration) }
    }

    @Test fun invalidEnvelopesAndMissingOrUnreadableKeysNeverCreateKey() {
        val creations = AtomicInteger()
        val missing =
            CredentialCipher { create ->
                if (create) creations.incrementAndGet()
                null
            }
        val valid = cipher.encrypt("tokens.a", "synthetic")
        val legacy = legacy("synthetic")
        listOf(valid, legacy, "v3:${valid.removePrefix("v2:")}", "v2:bad:bad", "bad", "$valid:extra").forEach {
            assertNull(missing.decrypt("tokens.a", it))
        }
        val unavailable =
            CredentialCipher { create ->
                assertFalse(create)
                error("synthetic-sensitive-provider-message")
            }
        assertNull(unavailable.decrypt("tokens.a", valid))
        assertEquals(0, creations.get())
        val parts = valid.split(':').toMutableList()
        val corrupted =
            Base64.decode(parts[2], Base64.NO_WRAP).apply {
                this[lastIndex] =
                    (this[lastIndex].toInt() xor 1).toByte()
            }
        parts[2] = Base64.encodeToString(corrupted, Base64.NO_WRAP)
        assertNull(cipher.decrypt("tokens.a", parts.joinToString(":")))
        assertNull(cipher.decrypt("tokens.a", "v2:$legacy"))
    }

    @Test fun failedMigrationCommitReturnsUnavailableEvenWhenMemoryWasPublished() {
        putLegacy("basic.a", "password")
        val commits = AtomicInteger()
        val failing =
            wrapPreferences {
                commits.incrementAndGet()
                false
            }
        val subject = KeystoreCredentialStore(context, failing, cipher)
        assertNull(subject.readBasicPassword("a"))
        assertEquals(1, commits.get())
        // Android commit(false) can publish the in-memory map before disk persistence fails.
        assertTrue(requireNotNull(preferences.getString("basic.a", null)).startsWith("v2:"))
        assertEquals("password", store.readBasicPassword("a"))
    }

    @Test fun failedMigrationEncryptionLeavesLegacyAndNeverRequestsNewKey() {
        val original = putLegacy("basic.a", "password")
        val calls = AtomicInteger()
        val unavailableOnRewrite =
            CredentialCipher { create ->
                assertFalse(create)
                if (calls.incrementAndGet() == 1) key else null
            }
        assertNull(KeystoreCredentialStore(context, preferences, unavailableOnRewrite).readBasicPassword("a"))
        assertEquals(original, preferences.getString("basic.a", null))
    }

    @Test fun pendingMismatchExpiryAndOneUseConsumptionPreserveSemantics() {
        putLegacy("pending.oidc", pending.encode())
        assertNull(store.consumePendingLogin("different", 1_001))
        assertTrue(requireNotNull(preferences.getString("pending.oidc", null)).startsWith("v2:"))
        assertEquals(pending, store.consumePendingLogin("state", 1_001))
        assertNull(store.consumePendingLogin("state", 1_001))
        putLegacy("pending.oidc", pending.encode())
        assertNull(store.consumePendingLogin("state", 601_001))
        assertFalse(preferences.contains("pending.oidc"))
        putLegacy("pending.oidc", pending.encode())
        val failing = KeystoreCredentialStore(context, wrapPreferences { false }, cipher)
        assertThrows(IllegalStateException::class.java) { failing.consumePendingLogin("state", 1_001) }
    }

    @Test fun migrationCannotOverwriteConcurrentRefreshAcrossStoreInstances() =
        interleaving { other ->
            other.saveTokens("a", tokens.copy(accessToken = "rotated"))
            assertEquals("rotated", other.readTokens("a")?.accessToken)
        }

    @Test fun migrationCannotResurrectConcurrentRemovalAcrossStoreInstances() =
        interleaving { other ->
            other.remove("a")
            assertNull(other.readTokens("a"))
            assertFalse(preferences.contains("tokens.a"))
        }

    private fun interleaving(mutation: (KeystoreCredentialStore) -> Unit) {
        putLegacy("tokens.a", "access\u0000refresh\u0000-1\u0000bearer\u0000openid")
        val migrationEntered = CountDownLatch(1)
        val releaseMigration = CountDownLatch(1)
        val mutationStarted = CountDownLatch(1)
        val blockedCipher =
            CredentialCipher { create ->
                assertFalse(create)
                migrationEntered.countDown()
                check(releaseMigration.await(10, TimeUnit.SECONDS))
                key
            }
        val subject = KeystoreCredentialStore(context, preferences, blockedCipher)
        val executor = Executors.newFixedThreadPool(2)
        try {
            val read = executor.submit<AuthTokens?> { subject.readTokens("a") }
            assertTrue(migrationEntered.await(5, TimeUnit.SECONDS))
            val change =
                executor.submit {
                    mutationStarted.countDown()
                    mutation(store)
                }
            assertTrue(mutationStarted.await(5, TimeUnit.SECONDS))
            releaseMigration.countDown()
            assertEquals("access", read.get(10, TimeUnit.SECONDS)?.accessToken)
            change.get(10, TimeUnit.SECONDS)
        } finally {
            releaseMigration.countDown()
            executor.shutdownNow()
        }
    }

    private fun registrationJson() =
        JSONArray(
            listOf(
                registration.serverUrl,
                registration.issuer,
                registration.clientId,
                registration.redirectUri,
                registration.authorizationEndpoint,
                registration.tokenEndpoint,
                registration.source.name,
                registration.registrationAccessToken,
                registration.registrationClientUri,
            ),
        ).toString()

    private fun putLegacy(
        slot: String,
        value: String,
    ): String =
        legacy(value).also {
            check(preferences.edit().putString(slot, it).commit())
        }

    private fun legacy(value: String): String =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, key)
            listOf(
                iv,
                doFinal(value.toByteArray(Charsets.UTF_8)),
            ).joinToString(":") { Base64.encodeToString(it, Base64.NO_WRAP) }
        }

    private fun wrapPreferences(afterCommit: () -> Boolean): SharedPreferences =
        Proxy.newProxyInstance(
            SharedPreferences::class.java.classLoader,
            arrayOf(SharedPreferences::class.java),
        ) { _, method, args ->
            if (method.name == "edit") {
                val editor = preferences.edit()
                Proxy.newProxyInstance(
                    SharedPreferences.Editor::class.java.classLoader,
                    arrayOf(SharedPreferences.Editor::class.java),
                ) { instance, operation, values ->
                    if (operation.name == "commit") {
                        editor.commit()
                        afterCommit()
                    } else {
                        operation.invoke(editor, *values.orEmpty())
                        instance
                    }
                }
            } else {
                method.invoke(preferences, *args.orEmpty())
            }
        } as SharedPreferences
}
