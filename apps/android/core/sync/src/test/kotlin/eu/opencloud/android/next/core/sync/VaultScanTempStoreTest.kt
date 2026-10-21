package eu.opencloud.android.next.core.sync

import android.content.Context
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import java.io.File

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VaultScanTempStoreTest {
    @Test fun processStartupClearsInterruptedOutputAndSessionRejectsForeignFiles() {
        val context: Context = RuntimeEnvironment.getApplication()
        val root = File(context.noBackupFilesDir, "vault-scan-temp")
        assertTrue(root.mkdirs() || root.isDirectory)
        val interrupted = File(root, "interrupted").apply { mkdirs() }
        File(interrupted, "page.pdf").writeText("stale")

        VaultScanTempStore.initializeProcess(context)
        assertTrue(root.isDirectory)
        assertEquals(0, root.listFiles().orEmpty().size)

        val store = VaultScanTempStore(context)
        val session = store.createSession()
        val output = File(session.outputDirectory, "scan.pdf").apply { writeText("current") }
        assertEquals(listOf(output.canonicalFile), session.validatedFiles(listOf(output)))

        val outside = File(context.cacheDir, "unowned-scan.pdf").apply { writeText("outside") }
        try {
            session.validatedFiles(listOf(outside))
            throw AssertionError("Foreign scanner output should be rejected.")
        } catch (_: IllegalArgumentException) {
            assertTrue(outside.exists())
        }

        session.discard()
        assertFalse(output.parentFile!!.exists())
        assertTrue(outside.delete())
    }
}
