package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files

class VaultDirectoryIndexTest {
    @Test
    fun `external runs page every child once with stable folder and case ordering`() {
        val root = Files.createTempDirectory("vault-directory-test").toFile()
        try {
            val entries =
                (0 until 1537).map { number ->
                    val name = if (number % 2 == 0) "Private-${number % 99}" else "private-${number % 99}"
                    row(number, name, number % 5 == 0)
                }
            VaultDirectoryIndex(root) {}.use { index ->
                entries.reversed().forEach(index::add)
                index.finish()
                assertEquals(1537L, index.count)
                val read = mutableListOf<VaultFolder>()
                var offset = 0L
                while (offset < index.count) {
                    val page = index.page(offset, 127)
                    assertTrue(page.size in 1..127)
                    read += page
                    offset += page.size
                }
                val expected =
                    entries.sortedWith(
                        compareBy<VaultFolder> { !it.isFolder }
                            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
                            .thenBy { it.name }
                            .thenBy { it.encryptedPath }
                            .thenBy { it.id },
                    )
                assertEquals(expected, read)
                assertTrue(index.page(index.count, 128).isEmpty())
                root.walkTopDown().filter(File::isFile).forEach { file ->
                    assertFalse(file.readBytes().toString(Charsets.ISO_8859_1).contains("Private-"))
                }
            }
            assertTrue(root.listFiles().orEmpty().isEmpty())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun `interrupted sort cleanup removes every temporary run`() {
        val root = Files.createTempDirectory("vault-directory-cancel-test").toFile()
        var active = true
        try {
            VaultDirectoryIndex(root) { if (!active) throw CancellationException() }.use { index ->
                repeat(257) { index.add(row(it, "secret-$it", false)) }
                active = false
                assertThrows(CancellationException::class.java) { index.finish() }
            }
            assertTrue(root.listFiles().orEmpty().isEmpty())
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun `authenticated row corruption fails before any page is returned`() {
        val root = Files.createTempDirectory("vault-directory-auth-test").toFile()
        try {
            VaultDirectoryIndex(root) {}.use { index ->
                index.add(row(1, "secret", false))
                index.finish()
                val rows = root.walkTopDown().single { it.isFile && it.name != "offsets" }
                RandomAccessFile(rows, "rw").use { file ->
                    file.seek(file.length() - 1)
                    val value = file.readByte().toInt()
                    file.seek(file.length() - 1)
                    file.writeByte(value xor 1)
                }
                assertThrows(OpenCloudException::class.java) { index.page(0, 128) }
            }
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun `Unicode ordering preserves browser case insensitive comparison across run boundaries`() {
        val root = Files.createTempDirectory("vault-directory-unicode-test").toFile()
        try {
            // ROOT lowercase sorts dotless i after z; CASE_INSENSITIVE_ORDER groups I/i/İ/ı.
            val names = listOf("Z", "i", "İ", "ı", "I", "a", "Σ", "σ", "ς", "Å", "å")
            val entries = (0 until 513).map { row(it, names[it % names.size], it % 7 == 0) }
            VaultDirectoryIndex(root) {}.use { index ->
                entries.reversed().forEach(index::add)
                index.finish()
                val expected =
                    entries.sortedWith(
                        compareBy<VaultFolder> { !it.isFolder }
                            .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
                            .thenBy { it.name }
                            .thenBy { it.encryptedPath }
                            .thenBy { it.id },
                    )
                val read = mutableListOf<VaultFolder>()
                while (read.size < index.count) read += index.page(read.size.toLong(), 113)
                assertEquals(expected, read)
                assertTrue(
                    read.indexOfFirst { !it.isFolder && it.name == "ı" } <
                        read.indexOfFirst { !it.isFolder && it.name == "Z" },
                )
            }
        } finally {
            root.deleteRecursively()
        }
    }

    @Test
    fun `new stages remove owned orphans and preserve active malformed and symlink siblings`() {
        val root = Files.createTempDirectory("vault-directory-cleanup-test").toFile()
        val outside = Files.createTempDirectory("vault-directory-outside-test").toFile()
        val linked = File(root, "vault-directory-${java.util.UUID.randomUUID()}")
        try {
            val orphan = File(root, "vault-directory-${java.util.UUID.randomUUID()}").apply { mkdir() }
            File(orphan, "offsets").writeBytes(byteArrayOf(1, 2, 3))
            val malformed = File(root, "vault-directory-not-a-uuid").apply { mkdir() }
            val preserved = File(malformed, "recovery").apply { writeText("preserve") }
            val outsideFile = File(outside, "recovery").apply { writeText("preserve") }
            Files.createSymbolicLink(linked.toPath(), outside.toPath())
            VaultDirectoryIndex(root) {}.use { first ->
                first.add(row(1, "first", false))
                first.finish()
                VaultDirectoryIndex(root) {}.use { second ->
                    second.add(row(2, "second", false))
                    second.finish()
                    assertFalse(orphan.exists())
                    assertEquals("first", first.page(0, 128).single().name)
                    assertEquals("second", second.page(0, 128).single().name)
                    assertTrue(Files.isSymbolicLink(linked.toPath()))
                    assertEquals("preserve", outsideFile.readText())
                    assertEquals("preserve", preserved.readText())
                }
                assertEquals("first", first.page(0, 128).single().name)
            }
        } finally {
            linked.delete()
            root.deleteRecursively()
            outside.deleteRecursively()
        }
    }

    @Test
    fun `stage parent through a symlink is refused without touching its target`() {
        val root = Files.createTempDirectory("vault-directory-parent-test").toFile()
        val outside = Files.createTempDirectory("vault-directory-parent-outside-test").toFile()
        val linked = File(root, "linked-parent")
        try {
            val preserved = File(outside, "recovery").apply { writeText("preserve") }
            Files.createSymbolicLink(linked.toPath(), outside.toPath())
            assertThrows(OpenCloudException::class.java) { VaultDirectoryIndex(linked) {} }
            assertEquals("preserve", preserved.readText())
            assertEquals(listOf("recovery"), outside.listFiles().orEmpty().map(File::getName))
        } finally {
            linked.delete()
            root.deleteRecursively()
            outside.deleteRecursively()
        }
    }

    @Test
    fun `a trusted parent below an Android style ancestor alias remains usable`() {
        val root = Files.createTempDirectory("vault-directory-alias-test").toFile()
        val target = Files.createTempDirectory("vault-directory-alias-target-test").toFile()
        val alias = File(root, "app-private-alias")
        try {
            File(target, "no-backup").mkdir()
            Files.createSymbolicLink(alias.toPath(), target.toPath())
            VaultDirectoryIndex(File(alias, "no-backup")) {}.use { index ->
                index.add(row(1, "usable", false))
                index.finish()
                assertEquals("usable", index.page(0, 128).single().name)
            }
            assertTrue(File(target, "no-backup").listFiles().orEmpty().isEmpty())
        } finally {
            alias.delete()
            root.deleteRecursively()
            target.deleteRecursively()
        }
    }

    private fun row(
        number: Int,
        name: String,
        folder: Boolean,
    ) = VaultFolder(
        number.toString(),
        name,
        "opaque-$number",
        name,
        "root/opaque-$number",
        folder,
        48L,
        "\"tag\"",
    )
}
