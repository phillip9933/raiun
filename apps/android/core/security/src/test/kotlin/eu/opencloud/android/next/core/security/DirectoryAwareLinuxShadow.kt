package eu.opencloud.android.next.core.security

import android.system.ErrnoException
import android.system.OsConstants
import android.system.StructStat
import org.robolectric.annotation.Implementation
import org.robolectric.annotation.Implements
import org.robolectric.annotation.RealObject
import org.robolectric.shadow.api.Shadow
import org.robolectric.shadows.ShadowLinux
import org.robolectric.util.ReflectionHelpers.ClassParameter
import java.io.File
import java.io.FileDescriptor
import java.util.Collections
import java.util.IdentityHashMap

/**
 * Models directory descriptors missing from pinned Robolectric 4.16.1's RandomAccessFile-based
 * ShadowLinux. Directory fsync is a model operation, not evidence of persistence or crash durability.
 * The separate LegacyCertificatePinStoreAndroidTest exercises real Android AtomicFile/fsync.
 * Regular-file operations retain the pinned shadow's behavior.
 */
@Implements(className = "libcore.io.Linux", isInAndroidSdk = false)
class DirectoryAwareLinuxShadow : ShadowLinux() {
    @RealObject private lateinit var realLinux: Any
    private val directories = Collections.synchronizedMap(IdentityHashMap<FileDescriptor, String>())
    private val closedDirectories =
        Collections.synchronizedSet(Collections.newSetFromMap(IdentityHashMap<FileDescriptor, Boolean>()))

    @Implementation
    override fun open(
        path: String,
        flags: Int,
        mode: Int,
    ): FileDescriptor {
        if (flags != OsConstants.O_RDONLY || !File(path).isDirectory) return super.open(path, flags, mode)
        return FileDescriptor().also { directories[it] = path }
    }

    @Implementation
    override fun fstat(descriptor: FileDescriptor): StructStat {
        requireOpen(descriptor, "fstat")
        val path = directories[descriptor] ?: return super.fstat(descriptor)
        return super.stat(path)
    }

    @Implementation
    fun fsync(descriptor: FileDescriptor) {
        requireOpen(descriptor, "fsync")
        if (descriptor !in directories) direct("fsync", descriptor)
    }

    @Implementation
    fun close(descriptor: FileDescriptor) {
        requireOpen(descriptor, "close")
        if (directories.remove(descriptor) != null) {
            closedDirectories += descriptor
        } else {
            direct("close", descriptor)
        }
    }

    private fun requireOpen(
        descriptor: FileDescriptor,
        operation: String,
    ) {
        if (descriptor in closedDirectories) throw ErrnoException(operation, OsConstants.EBADF)
    }

    private fun direct(
        method: String,
        descriptor: FileDescriptor,
    ) {
        Shadow.directlyOn<Any?>(
            realLinux,
            "libcore.io.Linux",
            method,
            ClassParameter.from(FileDescriptor::class.java, descriptor),
        )
    }
}
