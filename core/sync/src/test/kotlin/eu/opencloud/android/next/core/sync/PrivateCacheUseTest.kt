package eu.opencloud.android.next.core.sync

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.nio.file.Files

class PrivateCacheUseTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun `independent readers keep a file until the last idempotent close`() =
        runTest {
            val file = temporary.newFile()
            val first = LocalCopyLease.acquire(file)
            val second = LocalCopyLease.acquire(file)
            first.close()
            first.close()
            assertFalse(PrivateCacheUse.removeIfUnused(file) { true })
            second.close()
            assertTrue(PrivateCacheUse.removeIfUnused(file) { true })
        }

    @Test fun `cleanup cannot remove staging or unpublished target under an active writer`() =
        runTest {
            val staging = temporary.newFile("download.part")
            val target = temporary.newFile("target")
            PrivateCacheUse.hold(listOf(staging, target)) {
                assertFalse(PrivateCacheUse.removeIfUnused(staging) { true })
                assertFalse(PrivateCacheUse.removeIfUnused(target) { true })
                assertTrue(staging.exists())
                assertTrue(target.exists())
            }
            assertTrue(PrivateCacheUse.removeIfUnused(staging) { true })
            assertFalse(PrivateCacheUse.removeIfUnused(target) { false })
            assertTrue(target.exists())
        }

    @Test fun `cancellation releases ownership only after writer teardown`() =
        runTest {
            val file = temporary.newFile()
            val started = CompletableDeferred<Unit>()
            val writer =
                launch {
                    PrivateCacheUse.hold(listOf(file)) {
                        started.complete(Unit)
                        try {
                            awaitCancellation()
                        } finally {
                            withContext(NonCancellable) {
                                assertFalse(PrivateCacheUse.removeIfUnused(file) { true })
                            }
                        }
                    }
                }
            started.await()
            writer.cancelAndJoin()
            assertTrue(PrivateCacheUse.removeIfUnused(file) { true })
        }

    @Test fun `nested owners and duplicate paths retain protection until last release`() =
        runTest {
            val file = temporary.newFile()
            PrivateCacheUse.hold(listOf(file, file)) {
                PrivateCacheUse.hold(listOf(file)) {
                    assertFalse(PrivateCacheUse.removeIfUnused(file) { true })
                }
                assertFalse(PrivateCacheUse.removeIfUnused(file) { true })
            }
            assertTrue(PrivateCacheUse.removeIfUnused(file) { true })
        }

    @Test fun `symlink aliases share the same lease identity`() =
        runTest {
            val realDirectory = temporary.newFolder("real-cache")
            val aliasDirectory = File(temporary.root, "cache-alias")
            Files.createSymbolicLink(aliasDirectory.toPath(), realDirectory.toPath())
            val file = File(realDirectory, "cached-copy").apply { writeText("cached") }
            val aliasedFile = File(aliasDirectory, file.name)
            val lease = LocalCopyLease.acquire(file)

            assertFalse(PrivateCacheUse.removeIfUnused(aliasedFile) { true })
            assertTrue(file.exists())

            lease.close()
            assertTrue(PrivateCacheUse.removeIfUnused(aliasedFile) { true })
            assertFalse(file.exists())
        }
}
