package eu.opencloud.android.next.core.security

import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.lang.reflect.Proxy

class BasicCredentialPersistenceTest {
    @Test fun `both encrypted fields use one checked commit with existing keys`() {
        val storage = Storage()
        persistBasicCredentials(storage.preferences, "account", "alice", "secret") { "encrypted:$it" }
        assertEquals(
            mapOf("basic.username.account" to "encrypted:alice", "basic.account" to "encrypted:secret"),
            storage.values,
        )
        assertEquals(1, storage.edits)
        assertEquals(1, storage.commits)
    }

    @Test fun `failed commit propagates without publishing half a credential`() {
        val storage = Storage(commitSucceeds = false)
        assertThrows(IllegalStateException::class.java) {
            persistBasicCredentials(storage.preferences, "account", "alice", "secret") { "encrypted:$it" }
        }
        assertEquals(2, storage.staged.size)
        assertEquals(emptyMap<String, String>(), storage.values)
        assertEquals(1, storage.commits)
    }

    @Test fun `validation and encryption failure leave old credentials unchanged`() {
        val storage = Storage()
        storage.values["basic.account"] = "old"
        assertThrows(IllegalArgumentException::class.java) {
            persistBasicCredentials(storage.preferences, "account", "", "secret") { it }
        }
        assertThrows(IllegalStateException::class.java) {
            persistBasicCredentials(storage.preferences, "account", "alice", "secret") {
                if (it == "secret") error("Encryption failed.") else "encrypted:$it"
            }
        }
        assertEquals(mapOf("basic.account" to "old"), storage.values)
        assertEquals(0, storage.edits)
    }

    private class Storage(
        private val commitSucceeds: Boolean = true,
    ) {
        val values = mutableMapOf<String, String>()
        val staged = mutableMapOf<String, String>()
        var edits = 0
        var commits = 0
        private val editor =
            proxy(SharedPreferences.Editor::class.java) { method, args, instance ->
                when (method) {
                    "putString" -> {
                        staged[args[0] as String] = args[1] as String
                        instance
                    }
                    "commit" -> {
                        commits++
                        if (commitSucceeds) values.putAll(staged)
                        commitSucceeds
                    }
                    else -> error("Unexpected editor operation: $method")
                }
            }
        val preferences =
            proxy(SharedPreferences::class.java) { method, _, _ ->
                check(method == "edit")
                edits++
                editor
            }
    }
}

private fun <T : Any> proxy(
    type: Class<T>,
    invoke: (String, Array<out Any?>, Any) -> Any?,
): T =
    requireNotNull(
        type.cast(
            Proxy.newProxyInstance(type.classLoader, arrayOf(type)) { instance, method, args ->
                invoke(method.name, args.orEmpty(), instance)
            },
        ),
    )
