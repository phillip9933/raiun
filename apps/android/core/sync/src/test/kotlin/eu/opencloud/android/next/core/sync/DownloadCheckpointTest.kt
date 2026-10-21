package eu.opencloud.android.next.core.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class DownloadCheckpointTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun `only matching version resumes and metadata stores no raw location`() {
        val partial = temporary.newFile("part")
        val validator = temporary.newFile("validator")
        partial.writeText("old")
        val identity = "version https://cloud.example/private-name"
        assertEquals(0, prepareDownloadCheckpoint(partial, validator, identity, 10, true))
        assertEquals(0, partial.length())
        partial.writeText("hello")
        assertEquals(5, prepareDownloadCheckpoint(partial, validator, identity, 10, true))
        assertFalse(validator.readText().contains("private-name"))
        assertEquals(0, prepareDownloadCheckpoint(partial, validator, "changed", 10, true))
        partial.writeText("hello")
        assertEquals(0, prepareDownloadCheckpoint(partial, validator, "changed", 10, false))
        partial.writeText("helloworld")
        assertEquals(0, prepareDownloadCheckpoint(partial, validator, "changed", 10, true))
    }
}
