package eu.opencloud.android.next.core.sync

import android.util.AtomicFile
import java.io.File

// Older Android versions move the last committed contents to .bak while writing.
internal fun hasSavedAtomicFile(file: AtomicFile): Boolean =
    file.baseFile.isFile || File(file.baseFile.path + ".bak").isFile

internal fun readSavedAtomicFile(
    file: AtomicFile,
    maxBytes: Long,
): ByteArray {
    require(maxOf(file.baseFile.length(), File(file.baseFile.path + ".bak").length()) <= maxBytes)
    return file.readFully()
}
