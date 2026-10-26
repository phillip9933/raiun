package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.RemoteFolderEntry
import eu.opencloud.android.next.core.network.RemoteResource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** Exercises the actual Android SQLite and crypto implementations across a staging batch boundary. */
@RunWith(AndroidJUnit4::class)
class StagedRemoteFolderAndroidTest {
    @Test fun nativeStagePagesAuthenticatedRowsAndDeletesEncryptedTempFile() {
        val cache =
            File(
                InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,
                "native-stage-${System.nanoTime()}",
            ).apply { mkdirs() }
        val marker = "private-native-sentinel"
        try {
            val stage = StagedRemoteFolder.create(cache)
            val file = File(cache, "discovery-stage").listFiles().orEmpty().single { it.name.endsWith(".sqlite") }
            try {
                repeat(131) { index ->
                    val id = "id-$index"
                    val path = "/$marker-$index"
                    assertTrue(stage.registerCanonicalPath("dav/$marker-$index"))
                    stage.add(
                        RemoteFolderEntry(
                            id,
                            path,
                            RemoteResource(id, path, "$marker-$index", false, null, 1, null, 0, 0),
                        ),
                    )
                }
                stage.finish()
                val first = stage.page(0)
                val second = stage.page(first.last().sequence)
                assertEquals(128, first.size)
                assertEquals(3, second.size)
                assertEquals(
                    "$marker-130",
                    second
                        .last()
                        .entry.resource
                        ?.name,
                )
                assertTrue(stage.containsId("id-130"))
                assertFalse(stage.containsId("absent"))
                assertFalse(file.readBytes().containsAscii(marker.toByteArray(Charsets.US_ASCII)))
            } finally {
                stage.close()
            }
            assertFalse(file.exists())
            assertTrue(File(cache, "discovery-stage").listFiles().isNullOrEmpty())
        } finally {
            cache.deleteRecursively()
        }
    }

    private fun ByteArray.containsAscii(needle: ByteArray): Boolean =
        indices.any { start ->
            start + needle.size <= size && needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }
}
