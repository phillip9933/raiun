package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.RemoteFolderEntry
import eu.opencloud.android.next.core.network.RemoteResource
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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

    @Test fun stageSupportsSequentialDispatcherThreadHopsAndRejectsPartialPublication() {
        val cache =
            File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "hop-stage-${System.nanoTime()}")
        val first = Executors.newSingleThreadExecutor()
        val second = Executors.newSingleThreadExecutor()
        try {
            val stage = first.submit(Callable { StagedRemoteFolder.create(cache) }).get(10, TimeUnit.SECONDS)
            try {
                repeat(131) { index ->
                    val worker = if (index % 2 == 0) first else second
                    worker
                        .submit(
                            Callable {
                                assertTrue(stage.registerCanonicalPath("dav/$index"))
                                assertFalse(stage.registerCanonicalPath("dav/$index"))
                                assertTrue(stage.registerCollectionId("collection-$index"))
                                stage.add(RemoteFolderEntry("id-$index", "/$index", null))
                                assertFalse(stage.registerCollectionId("id-$index"))
                            },
                        ).get(10, TimeUnit.SECONDS)
                }
                assertThrows(IllegalStateException::class.java) { stage.page(0) }
                second.submit(Callable { stage.finish() }).get(10, TimeUnit.SECONDS)
                val page = first.submit(Callable { stage.page(0) }).get(10, TimeUnit.SECONDS)
                assertEquals(128, page.size)
                assertEquals(
                    3,
                    second.submit(Callable { stage.page(page.last().sequence).size }).get(10, TimeUnit.SECONDS),
                )
                assertThrows(IllegalStateException::class.java) { stage.add(RemoteFolderEntry("late", "/late", null)) }
            } finally {
                second.submit(Callable { stage.close() }).get(10, TimeUnit.SECONDS)
            }
            assertTrue(File(cache, "discovery-stage").listFiles().isNullOrEmpty())
        } finally {
            first.shutdownNow()
            second.shutdownNow()
            cache.deleteRecursively()
        }
    }

    @Test fun duplicateIdentitiesRejectBothBufferedAndCommittedRows() {
        val cache =
            File(
                InstrumentationRegistry.getInstrumentation().targetContext.cacheDir,
                "duplicate-stage-${System.nanoTime()}",
            )
        try {
            listOf(1, 128).forEach { count ->
                listOf(true, false).forEach { duplicateId ->
                    StagedRemoteFolder.create(cache).use { stage ->
                        repeat(count) { index -> stage.add(RemoteFolderEntry("id-$index", "/$index", null)) }
                        val entry =
                            if (duplicateId) {
                                RemoteFolderEntry(
                                    "id-0",
                                    "/new",
                                    null,
                                )
                            } else {
                                RemoteFolderEntry("new", "/0", null)
                            }
                        assertThrows(
                            eu.opencloud.android.next.core.network.OpenCloudException::class.java,
                        ) { stage.add(entry) }
                        assertThrows(IllegalStateException::class.java) { stage.finish() }
                        assertThrows(IllegalStateException::class.java) { stage.page(0) }
                    }
                }
            }
        } finally {
            cache.deleteRecursively()
        }
    }

    private fun ByteArray.containsAscii(needle: ByteArray): Boolean =
        indices.any { start ->
            start + needle.size <= size && needle.indices.all { offset -> this[start + offset] == needle[offset] }
        }
}
