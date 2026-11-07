package eu.opencloud.android.next.core.security

import android.content.Context
import android.content.SharedPreferences
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.TransportPolicyException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Exercises Android AtomicFile/fsync using uniquely named synthetic fixtures only. */
@RunWith(AndroidJUnit4::class)
class LegacyCertificatePinStoreAndroidTest {
    @Test fun migrationReopensDurablePolicyAndRemovesOnlyLegacyPinKeys() =
        withFixture { directory, preferences ->
            assertTrue(
                preferences
                    .edit()
                    .putStringSet("pins.$HOST", setOf(PIN))
                    .putStringSet("pins.other.example.test", setOf(OTHER_PIN))
                    .putString("unrelated", "synthetic-preserved-value")
                    .commit(),
            )

            assertEquals(setOf(PIN), LegacyCertificatePinStore(directory, preferences).pinsFor(HOST))

            val target = File(directory, "legacy-v1.bin")
            assertTrue(target.isFile && target.length() > 0)
            assertFalse(preferences.contains("pins.$HOST"))
            assertFalse(preferences.contains("pins.other.example.test"))
            assertEquals("synthetic-preserved-value", preferences.getString("unrelated", null))
            val published = target.readBytes()
            val reopened = LegacyCertificatePinStore(directory, preferences)
            assertEquals(setOf(PIN), reopened.pinsFor(HOST))
            assertEquals(setOf(OTHER_PIN), reopened.pinsFor("other.example.test"))
            assertTrue(reopened.pinsFor("unconfigured.example.test").isEmpty())
            assertArrayEquals(published, target.readBytes())
        }

    @Test fun corruptionAfterMigrationRefusesTrustInsteadOfReturningAnUnpinnedPolicy() =
        withFixture { directory, preferences ->
            assertTrue(preferences.edit().putStringSet("pins.$HOST", setOf(PIN)).commit())
            assertEquals(setOf(PIN), LegacyCertificatePinStore(directory, preferences).pinsFor(HOST))
            assertFalse(preferences.contains("pins.$HOST"))
            val target = File(directory, "legacy-v1.bin")
            // Change the first host character while retaining a structurally canonical host.
            // The corruption checksum must reject it before the original host can become unpinned.
            val corrupt = target.readBytes().apply { this[14] = 'x'.code.toByte() }
            target.writeBytes(corrupt)

            val failure =
                assertThrows(TransportPolicyException::class.java) {
                    LegacyCertificatePinStore(directory, preferences).pinsFor(HOST)
                }

            assertEquals(OpenCloudError.Trust, failure.error)
            assertEquals("The secure connection could not be verified.", failure.message)
            assertNull(failure.cause)
            assertArrayEquals(corrupt, target.readBytes())
        }

    private fun withFixture(action: (File, SharedPreferences) -> Unit) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val fixtureName = "synthetic-native-pin-migration-${UUID.randomUUID()}"
        val directory = File(context.noBackupFilesDir, fixtureName)
        val preferences = context.getSharedPreferences(fixtureName, Context.MODE_PRIVATE)
        try {
            action(directory, preferences)
        } finally {
            assertTrue(context.deleteSharedPreferences(fixtureName))
            assertTrue(!directory.exists() || directory.deleteRecursively())
        }
    }

    private companion object {
        const val HOST = "cloud_one.example.test"
        const val PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        const val OTHER_PIN = "sha256/AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    }
}
