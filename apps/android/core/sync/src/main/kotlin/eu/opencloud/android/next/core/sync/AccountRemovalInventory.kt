package eu.opencloud.android.next.core.sync

import java.io.File
import java.nio.file.Files

/** An unreadable or unexpected root must retain the removal marker, never masquerade as an empty inventory. */
internal fun accountRemovalInventory(root: File): List<File> {
    check(!Files.isSymbolicLink(root.toPath()))
    if (!root.exists()) return emptyList()
    check(root.isDirectory)
    return checkNotNull(root.listFiles()) { "Account payload inventory is not readable." }.toList().also { entries ->
        entries.forEach { check(it.isDirectory && !Files.isSymbolicLink(it.toPath())) }
    }
}
