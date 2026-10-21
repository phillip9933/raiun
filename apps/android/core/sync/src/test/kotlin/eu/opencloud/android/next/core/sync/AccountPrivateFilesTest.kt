package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.model.cacheIdentity
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.File

@RunWith(RobolectricTestRunner::class)
class AccountPrivateFilesTest {
    @Test fun `account cleanup removes downloads staged uploads and drafts without touching another account`() {
        val context = RuntimeEnvironment.getApplication()
        val roots =
            listOf(
                File(context.filesDir, "resources-v2"),
                File(context.noBackupFilesDir, "upload-sources"),
                File(context.noBackupFilesDir, "text-drafts"),
                File(context.noBackupFilesDir, "document-edits"),
            )
        val removed =
            roots.map {
                File(it, "${cacheIdentity("a/b")}/space/file").apply {
                    parentFile!!.mkdirs()
                    writeText("private")
                }
            }
        val retained =
            roots.map {
                File(it, "${cacheIdentity("a_b")}/space/file").apply {
                    parentFile!!.mkdirs()
                    writeText("other account")
                }
            }
        runBlocking { clearAccountPrivateFiles(context, "a/b") }
        removed.forEach { assertFalse(it.exists()) }
        retained.forEach { assertTrue(it.exists()) }
    }
}
