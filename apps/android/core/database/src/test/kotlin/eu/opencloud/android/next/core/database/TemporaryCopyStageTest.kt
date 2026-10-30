package eu.opencloud.android.next.core.database

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.UUID

class TemporaryCopyStageTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun staleDeadOwnerIsReclaimedWhileLiveUnknownAndSymlinkStagesArePreserved() {
        val directory = temporary.newFolder("stages")
        TemporaryCopyStage.create(directory).use { live ->
            age(live.file)
            age(File(live.file.path + ".owner"))
            val dead = orphan(directory)
            val sidecar = File(dead.path + "-journal").apply { writeText("private stage journal") }
            val unknown = orphan(directory, "not an inventory owner")
            val missingOwner = orphan(directory).also { File(it.path + ".owner").delete() }
            val outside = temporary.newFile("outside").apply { writeText("untouched") }
            val linkedDatabase = orphan(directory)
            assertTrue(linkedDatabase.delete())
            Files.createSymbolicLink(linkedDatabase.toPath(), outside.toPath())
            val linkedOwner = orphan(directory)
            val ownerPath = File(linkedOwner.path + ".owner").toPath()
            Files.delete(ownerPath)
            Files.createSymbolicLink(ownerPath, outside.toPath())
            val linkedSidecar = orphan(directory)
            Files.createSymbolicLink(File(linkedSidecar.path + "-wal").toPath(), outside.toPath())

            cleanupStaleTemporaryCopyStages(directory)

            assertFalse(dead.exists())
            assertFalse(File(dead.path + ".owner").exists())
            assertFalse(sidecar.exists())
            assertTrue(live.file.exists())
            assertTrue(unknown.exists())
            assertTrue(missingOwner.exists())
            assertTrue(Files.isSymbolicLink(linkedDatabase.toPath()))
            assertTrue(Files.isSymbolicLink(ownerPath))
            assertTrue(linkedSidecar.exists())
            assertEquals("untouched", outside.readText())
        }
    }

    @Test fun eachReclamationPassInspectsAtMost128CandidateFiles() {
        val directory = temporary.newFolder("bounded-stages")
        repeat(260) { orphan(directory) }
        cleanupStaleTemporaryCopyStages(directory)
        assertEquals(132, directory.listFiles().orEmpty().count { it.extension == "sqlite" })
        cleanupStaleTemporaryCopyStages(directory)
        assertEquals(4, directory.listFiles().orEmpty().count { it.extension == "sqlite" })
        cleanupStaleTemporaryCopyStages(directory)
        assertTrue(directory.listFiles().orEmpty().isEmpty())
    }

    @Test fun recentlyAbandonedOwnerIsRetainedUntilBothOwnerAndDatabaseAreOld() {
        val directory = temporary.newFolder("fresh-stages")
        val file = orphan(directory)
        val owner = File(file.path + ".owner")
        assertTrue(owner.setLastModified(System.currentTimeMillis()))
        cleanupStaleTemporaryCopyStages(directory)
        assertTrue(file.exists())
        age(owner)
        cleanupStaleTemporaryCopyStages(directory)
        assertFalse(file.exists())
        assertFalse(owner.exists())
    }

    @Test fun stagingDirectoryCannotBeASymbolicLink() {
        val actual = temporary.newFolder("actual")
        val link = File(temporary.root, "linked")
        Files.createSymbolicLink(link.toPath(), actual.toPath())
        assertThrows(IOException::class.java) { TemporaryCopyStage.create(link) }
        assertTrue(actual.listFiles().orEmpty().isEmpty())
    }

    private fun orphan(
        directory: File,
        marker: String = TEMPORARY_COPY_OWNER_MARKER,
    ): File =
        File(directory, "ordinary-inventory-${UUID.randomUUID()}.sqlite").apply {
            writeText("synthetic abandoned metadata")
            age(this)
            File(path + ".owner").apply {
                writeText(marker)
                age(this)
            }
        }

    private fun age(file: File) {
        assertTrue(file.setLastModified(1))
    }
}
