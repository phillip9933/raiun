package eu.opencloud.android.next.core.sync

import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption

/** Host fixtures use real JVM fsync because Robolectric's ShadowLinux cannot open directory FDs. */
internal fun jvmFsyncOfflineDirectory(directory: File) {
    if (!Files.isDirectory(directory.toPath(), LinkOption.NOFOLLOW_LINKS)) {
        throw IOException("Host offline sync target is not a directory")
    }
    FileChannel.open(directory.toPath(), StandardOpenOption.READ).use { it.force(true) }
}

/** Retains production confinement, parent ordering and injectable failure semantics around real IO. */
internal fun jvmOfflineDurability(
    boundary: File,
    beforeSync: (File) -> Unit = {},
): OfflineDurability =
    OfflineDurability(boundary) {
        beforeSync(it)
        jvmFsyncOfflineDirectory(it)
    }
