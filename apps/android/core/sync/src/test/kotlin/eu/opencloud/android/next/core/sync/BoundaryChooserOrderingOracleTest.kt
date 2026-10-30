package eu.opencloud.android.next.core.sync

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.util.Locale

/** Pure index compatibility oracle; synthetic opaque metadata sizes do not claim live DAV acceptance. */
class BoundaryChooserOrderingOracleTest {
    @Test fun destinationOrderUsesRootLowercaseAndStableWireTiesAcrossByteShortRunsAndPages() {
        val root = Files.createTempDirectory("chooser-order-oracle").toFile()
        val previous = Locale.getDefault()
        try {
            Locale.setDefault(Locale.forLanguageTag("tr-TR"))
            val names =
                (0 until 521)
                    .map { mask ->
                        "stablecase"
                            .mapIndexed { bit, character ->
                                if (mask and (1 shl bit) != 0) character.uppercaseChar() else character
                            }.joinToString("")
                    }.reversed() + listOf("İ", "i\u0307", "I", "i", "ß", "SS", "ss", "Σ", "σ", "ς", "é", "e\u0301", "É")
            val wire = names.mapIndexed { number, name -> row(number, name, "\"${"e".repeat(4_000)}\"") }
            val expected = wire.sortedBy { it.name.lowercase(Locale.ROOT) }
            VaultDirectoryIndex(root, VaultDirectoryOrder.DESTINATION) {}.use { index ->
                wire.forEach(index::add)
                index.finish()
                assertEquals(wire.size.toLong(), index.count)
                val actual = mutableListOf<VaultFolder>()
                val first = index.page(0, 128)
                assertTrue("A byte-budget page must shorten before the row-count limit", first.size in 1..127)
                actual += first
                while (actual.size < index.count) {
                    val page = index.page(actual.size.toLong(), 128)
                    assertTrue(page.size in 1..128)
                    actual += page
                }
                assertEquals(expected, actual)
                assertEquals(
                    wire.filter { it.name.lowercase(Locale.ROOT) == "stablecase" }.map { it.id },
                    actual.filter { it.name.lowercase(Locale.ROOT) == "stablecase" }.map { it.id },
                )
                assertEquals(
                    expected.filter(VaultFolder::isVaultRoot).map { it.id },
                    actual.filter(VaultFolder::isVaultRoot).map { it.id },
                )
            }
            assertTrue(root.listFiles().orEmpty().isEmpty())
        } finally {
            Locale.setDefault(previous)
            root.deleteRecursively()
        }
    }

    @Test fun defaultIndexOrderingRemainsTheExistingVaultFolderThenExactTieBreakContract() {
        val root = Files.createTempDirectory("vault-order-oracle").toFile()
        val wire = listOf(row(1, "z"), row(2, "A"), row(3, "a"), row(4, "b").copy(isFolder = false))
        val expected =
            wire.sortedWith(
                compareBy<VaultFolder> { !it.isFolder }
                    .thenBy(String.CASE_INSENSITIVE_ORDER) { it.name }
                    .thenBy { it.name }
                    .thenBy { it.encryptedPath }
                    .thenBy { it.id },
            )
        try {
            VaultDirectoryIndex(root) {}.use { index ->
                wire.forEach(index::add)
                index.finish()
                assertEquals(expected, index.page(0, 128))
            }
        } finally {
            root.deleteRecursively()
        }
    }

    private fun row(
        number: Int,
        name: String,
        version: String = "\"v1\"",
    ) = VaultFolder(
        id = "id-$number",
        name = name,
        rawName = "raw-$number",
        path = name,
        encryptedPath = "root.vault/raw-$number",
        isFolder = true,
        size = 0,
        strongETag = version,
        contentType = null,
        isVaultRoot = number % 17 == 0,
    )
}
