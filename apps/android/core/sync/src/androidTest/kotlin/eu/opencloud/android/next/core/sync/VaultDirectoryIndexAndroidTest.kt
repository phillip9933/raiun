package eu.opencloud.android.next.core.sync

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.network.OpenCloudException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.nio.file.Files
import java.util.UUID

/** Native app-private paths and AES-GCM provider behavior; synthetic entries only. */
@RunWith(AndroidJUnit4::class)
class VaultDirectoryIndexAndroidTest {
    @Test fun noBackupIndexEncryptsAndPagesEverySyntheticChild() {
        val root = createRoot()
        try {
            VaultDirectoryIndex(root) {}.use { index ->
                (0 until 1031).reversed().forEach { index.add(row(it)) }
                index.finish()
                assertEquals(1031L, index.count)
                val ids = mutableListOf<String>()
                while (ids.size < index.count) {
                    val page = index.page(ids.size.toLong(), 127)
                    assertTrue(page.size in 1..127)
                    ids += page.map(VaultFolder::id)
                }
                val expected = (0 until 1031).sortedWith(compareBy<Int> { it % 5 != 0 }.thenBy { it })
                assertEquals(expected.map(Int::toString), ids)
                assertEquals(1031, ids.toSet().size)
                assertTrue(index.page(index.count, 127).isEmpty())
                assertNamesStayEncrypted(root)
            }
            assertTrue(root.listFiles().orEmpty().isEmpty())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test fun canonicalParentKeepsActiveIndexesAndRemovesOnlyOwnedOrphans() {
        val root = createRoot()
        try {
            VaultDirectoryIndex(root) {}.use { first ->
                first.add(row(1))
                first.finish()
                val orphan = File(root, "vault-directory-${UUID.randomUUID()}").apply { mkdir() }
                File(orphan, "offsets").writeBytes(byteArrayOf(1, 2, 3))
                val unrelated = File(root, "recovery").apply { mkdir() }
                val preserved = File(unrelated, "evidence").apply { writeText("preserve") }
                VaultDirectoryIndex(root.canonicalFile) {}.use { second ->
                    second.add(row(2))
                    second.finish()
                    assertFalse(orphan.exists())
                    assertEquals("1", first.page(0, 128).single().id)
                    assertEquals("2", second.page(0, 128).single().id)
                    assertEquals("preserve", preserved.readText())
                }
                assertEquals("1", first.page(0, 128).single().id)
                preserved.delete()
                unrelated.delete()
            }
            assertTrue(root.listFiles().orEmpty().isEmpty())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test fun nativeAncestorAliasWorksAndLeafAndStageSymlinksStayConfined() {
        val root = createRoot()
        val target = File(root, "private-target").apply { mkdir() }
        val parent = File(target, "no-backup").apply { mkdir() }
        val alias = File(root, "private-alias")
        val stageLink = File(parent, "vault-directory-${UUID.randomUUID()}")
        val evidence = File(target, "evidence").apply { writeText("preserve") }
        try {
            Files.createSymbolicLink(alias.toPath(), target.toPath())
            Files.createSymbolicLink(stageLink.toPath(), target.toPath())
            VaultDirectoryIndex(File(alias, "no-backup")) {}.use { index ->
                index.add(row(7))
                index.finish()
                assertEquals("7", index.page(0, 128).single().id)
                assertTrue(Files.isSymbolicLink(stageLink.toPath()))
                assertEquals("preserve", evidence.readText())
            }
            assertThrows(OpenCloudException::class.java) { VaultDirectoryIndex(alias) {} }
            assertEquals("preserve", evidence.readText())
            assertTrue(Files.isSymbolicLink(stageLink.toPath()))
        } finally {
            stageLink.delete()
            alias.delete()
            root.deleteRecursively()
        }
    }

    private fun createRoot(): File {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        return File(context.noBackupFilesDir, "vault-index-native-${UUID.randomUUID()}").apply {
            assertTrue(mkdirs())
        }
    }

    private fun assertNamesStayEncrypted(root: File) {
        root.walkTopDown().filter(File::isFile).forEach { file ->
            val bytes = file.readBytes()
            try {
                assertFalse(bytes.toString(Charsets.ISO_8859_1).contains(PRIVATE_MARKER))
            } finally {
                bytes.fill(0)
            }
        }
    }

    private fun row(number: Int): VaultFolder {
        val name = PRIVATE_MARKER + number.toString().padStart(4, '0')
        return VaultFolder(
            number.toString(),
            name,
            "opaque-$number",
            name,
            "root/opaque-$number",
            number % 5 == 0,
            48L,
            "\"version\"",
        )
    }

    private companion object {
        const val PRIVATE_MARKER = "Distinctive-Native-Encrypted-Child-"
    }
}
