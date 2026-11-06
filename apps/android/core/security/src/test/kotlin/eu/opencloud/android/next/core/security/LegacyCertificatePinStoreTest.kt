package eu.opencloud.android.next.core.security

import android.content.Context
import android.content.SharedPreferences
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.TransportPolicyException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35], shadows = [DirectoryAwareLinuxShadow::class])
class LegacyCertificatePinStoreTest {
    @get:Rule val directoryModel = DirectoryLinuxModelRule()

    @get:Rule val temporary = TemporaryFolder()
    private val context: Context = RuntimeEnvironment.getApplication()
    private val preferences = context.getSharedPreferences("synthetic-legacy-pins", Context.MODE_PRIVATE)
    private val directory by lazy { File(temporary.root, "pins") }
    private val target get() = File(directory, "legacy-v1.bin")

    @Test fun `absent policy uses normal trust without creating a store`() {
        assertTrue(store().pinsFor(HOST).isEmpty())
        assertFalse(directory.exists())
    }

    @Test fun `migration durably validates every host before removing only legacy pin keys`() {
        put(HOST, PIN)
        put("other.example.test", OTHER_PIN)
        preferences.edit().putString("unrelated", "preserved").commit()
        var cleanupObserved = false
        val checked =
            object : SharedPreferences by preferences {
                override fun edit(): SharedPreferences.Editor {
                    val editor = preferences.edit()
                    return object : SharedPreferences.Editor by editor {
                        override fun commit(): Boolean {
                            assertTrue(target.isFile && target.length() > 0)
                            assertTrue(preferences.contains("pins.$HOST"))
                            cleanupObserved = true
                            return editor.commit()
                        }
                    }
                }
            }

        assertEquals(setOf(PIN), store(checked).pinsFor(HOST))

        assertTrue(cleanupObserved)
        assertFalse(preferences.contains("pins.$HOST"))
        assertFalse(preferences.contains("pins.other.example.test"))
        assertEquals("preserved", preferences.getString("unrelated", null))
        assertEquals(setOf(PIN), store().pinsFor(HOST))
        assertEquals(setOf(OTHER_PIN), store().pinsFor("other.example.test"))
        assertTrue(store().pinsFor("unconfigured.example.test").isEmpty())
    }

    @Test fun `host lookup is independent of Turkish default locale`() {
        put("i.example.test", PIN)
        val previous = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"))
            assertEquals(setOf(PIN), store().pinsFor("I.EXAMPLE.TEST"))
        } finally {
            Locale.setDefault(previous)
        }
    }

    @Test fun `typed malformed and ambiguous legacy data fail closed without removal`() {
        val corruptValues =
            listOf(
                mapOf("pins.$HOST" to "not-a-set"),
                mapOf("pins.$HOST" to setOf(PIN, 7)),
                mapOf("pins.$HOST" to setOf("sha256/not-a-digest")),
                mapOf("pins.*.example.test" to setOf(PIN)),
                mapOf("pins.I.example.test" to setOf(PIN)),
                mapOf("pins.ı.example.test" to setOf(PIN)),
            )
        corruptValues.forEach { values ->
            var edited = false
            val malformed =
                object : SharedPreferences by preferences {
                    override fun getAll(): MutableMap<String, *> = values.toMutableMap()

                    override fun edit(): SharedPreferences.Editor {
                        edited = true
                        return preferences.edit()
                    }
                }
            assertTrustFailure { store(malformed).pinsFor(HOST) }
            assertFalse(edited)
            assertFalse(directory.exists())
        }
    }

    @Test fun `failed publication retains preferences and can retry`() {
        put(HOST, PIN)
        directory.writeText("synthetic storage obstruction")

        assertTrustFailure { store().pinsFor(HOST) }

        assertTrue(preferences.contains("pins.$HOST"))
        assertEquals("synthetic storage obstruction", directory.readText())
        assertTrue(directory.delete())
        assertEquals(setOf(PIN), store().pinsFor(HOST))
    }

    @Test fun `interrupted cleanup retries from the validated durable store`() {
        put(HOST, PIN)
        val interrupted =
            object : SharedPreferences by preferences {
                override fun edit(): SharedPreferences.Editor {
                    val editor = preferences.edit()
                    return object : SharedPreferences.Editor by editor {
                        override fun commit(): Boolean = false
                    }
                }
            }
        assertTrustFailure { store(interrupted).pinsFor(HOST) }
        val durable = target.readBytes()
        assertTrue(preferences.contains("pins.$HOST"))

        assertEquals(setOf(PIN), store().pinsFor(HOST))

        assertTrue(target.readBytes().contentEquals(durable))
        assertFalse(preferences.contains("pins.$HOST"))
    }

    @Test fun `conflicting interrupted legacy policy cannot widen the durable policy`() {
        put(HOST, PIN)
        store().pinsFor(HOST)
        val durable = target.readBytes()
        put(HOST, OTHER_PIN)

        assertTrustFailure { store().pinsFor(HOST) }

        assertEquals(setOf(OTHER_PIN), preferences.getStringSet("pins.$HOST", null))
        assertTrue(target.readBytes().contentEquals(durable))
    }

    @Test fun `corrupt existing store blocks even an unrelated host and preserves recovery data`() {
        put(HOST, PIN)
        store().pinsFor(HOST)
        put(HOST, PIN)
        target.writeText("corrupt store")

        assertTrustFailure { store().pinsFor("unconfigured.example.test") }

        assertEquals("corrupt store", target.readText())
        assertTrue(preferences.contains("pins.$HOST"))
    }

    @Test fun `missing completed store cannot become an unpinned installation`() {
        put(HOST, PIN)
        store().pinsFor(HOST)
        assertTrue(target.delete())

        assertTrustFailure { store().pinsFor(HOST) }

        assertTrue(directory.isDirectory)
    }

    @Test fun `orphan pending and corrupt backup files remain available for recovery`() {
        assertTrue(directory.mkdirs())
        val pending = File(target.path + ".new").apply { writeText("pending") }
        put(HOST, PIN)
        assertTrustFailure { store().pinsFor(HOST) }
        assertEquals("pending", pending.readText())
        assertTrue(preferences.contains("pins.$HOST"))
        val backup = File(target.path + ".bak").apply { writeText("corrupt backup") }
        assertTrustFailure { store().pinsFor(HOST) }
        assertEquals("corrupt backup", backup.readText())
        assertEquals("pending", pending.readText())
    }

    @Test fun `valid atomic backup is enforced without deleting recovery sources`() {
        put(HOST, PIN)
        store().pinsFor(HOST)
        val durable = target.readBytes()
        val backup = File(target.path + ".bak").apply { writeBytes(durable) }
        target.writeText("interrupted replacement")

        assertEquals(setOf(PIN), store().pinsFor(HOST))

        assertTrue(backup.readBytes().contentEquals(durable))
        assertEquals("interrupted replacement", target.readText())
    }

    @Test fun `concurrent instances publish one complete policy`() {
        put(HOST, PIN)
        put("other.example.test", OTHER_PIN)
        val executor = Executors.newFixedThreadPool(4)
        try {
            val results = (1..16).map { executor.submit<Set<String>> { store().pinsFor(HOST) } }
            results.forEach { assertEquals(setOf(PIN), it.get(10, TimeUnit.SECONDS)) }
            assertEquals(setOf(OTHER_PIN), store().pinsFor("other.example.test"))
            assertFalse(preferences.contains("pins.$HOST"))
        } finally {
            executor.shutdownNow()
        }
    }

    @Test fun `bounded and unsupported store encodings fail closed`() {
        put(HOST, PIN)
        store().pinsFor(HOST)
        val original = target.readBytes()
        val invalid =
            listOf(
                original.copyOf(5),
                original + byteArrayOf(0),
                original.clone().apply { this[7] = 2 },
                original.clone().apply { this[14] = 'x'.code.toByte() }, // Still-canonical host mutation.
                ByteArray(65537),
            )
        invalid.forEach { bytes ->
            target.writeBytes(bytes)
            assertTrustFailure { store().pinsFor(HOST) }
            assertTrue(target.readBytes().contentEquals(bytes))
        }
    }

    private fun put(
        host: String,
        pin: String,
    ) {
        assertTrue(preferences.edit().putStringSet("pins.$host", setOf(pin)).commit())
    }

    private fun store(legacy: SharedPreferences = preferences) = LegacyCertificatePinStore(directory, legacy)

    private fun assertTrustFailure(action: () -> Unit) {
        val failure = assertThrows(TransportPolicyException::class.java) { action() }
        assertEquals(OpenCloudError.Trust, failure.error)
        assertEquals("The secure connection could not be verified.", failure.message)
        assertNull(failure.cause)
    }

    private companion object {
        const val HOST = "cloud_one.example.test"
        const val PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        const val OTHER_PIN = "sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    }
}
