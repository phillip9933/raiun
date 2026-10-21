package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

class UploadSourceTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun `unknown length is staged without transforming original bytes and retries ignore changed provider`() {
        val directory = temporary.newFolder()
        val original = byteArrayOf(0, 1, -1, 42, 0)
        val first = stageUploadSource(directory, -1, { original.inputStream() }, { Long.MAX_VALUE }, {})
        assertEquals(5L, first.length())
        val retry = stageUploadSource(directory, 5, { error("Provider must not be reopened") }, { Long.MAX_VALUE }, {})
        assertArrayEquals(original, retry.readBytes())
    }

    @Test fun `corrupted sealed source and insufficient storage fail before transfer`() {
        val directory = temporary.newFolder()
        val file = stageUploadSource(directory, 3, { "abc".byteInputStream() }, { Long.MAX_VALUE }, {})
        file.writeText("def")
        val corrupted =
            assertThrows(OpenCloudException::class.java) {
                stageUploadSource(directory, 3, { "abc".byteInputStream() }, { Long.MAX_VALUE }, {})
            }
        assertEquals(OpenCloudError.SourceChanged, corrupted.error)
        assertThrows(OpenCloudException::class.java) {
            stageUploadSource(temporary.newFolder(), -1, { "abc".byteInputStream() }, { 0 }, {})
        }
    }

    @Test fun `changed provider length asks for source reselection instead of remote refresh`() {
        listOf(2L, 4L).forEach { expected ->
            val directory = temporary.newFolder()
            val changed =
                assertThrows(OpenCloudException::class.java) {
                    stageUploadSource(directory, expected, { "abc".byteInputStream() }, { Long.MAX_VALUE }, {})
                }
            assertEquals(OpenCloudError.SourceChanged, changed.error)
            assertFalse(File(directory, "seal").exists())
        }
    }

    @Test fun `failed local payload replacement is not reported as insufficient space`() {
        val directory = temporary.newFolder()
        val blocked = File(directory, "payload").apply { mkdir() }
        File(blocked, "child").writeText("keep")
        val failed =
            assertThrows(OpenCloudException::class.java) {
                stageUploadSource(directory, 3, { "abc".byteInputStream() }, { Long.MAX_VALUE }, {})
            }
        assertEquals(OpenCloudError.LocalStorageWriteFailed, failed.error)
    }

    @Test fun `cancelled staging keeps cancellation and never seals partial bytes`() {
        val directory = temporary.newFolder()
        val cancellation = CancellationException("Stopped by the user")
        val result =
            assertThrows(CancellationException::class.java) {
                stageUploadSource(directory, -1, { "original".byteInputStream() }, { Long.MAX_VALUE }) {
                    throw cancellation
                }
            }
        assertSame(cancellation, result)
        assertFalse(File(directory, "payload").exists())
        assertFalse(File(directory, "seal").exists())
    }
}
