package eu.opencloud.android.next.core.documentsprovider

import android.os.ProxyFileDescriptorCallback
import android.system.ErrnoException
import android.system.OsConstants
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicBoolean

/** Read-only seekable adapter. A private file descriptor is never handed to another app. */
internal class SharedReadDescriptor(
    private val length: Long,
    private val read: suspend (Long, Int) -> ByteArray,
    private val release: () -> Unit,
) : ProxyFileDescriptorCallback() {
    private val closed = AtomicBoolean()

    override fun onGetSize(): Long =
        guarded {
            runBlocking { read(0, 0) }
            length
        }

    override fun onRead(
        offset: Long,
        size: Int,
        data: ByteArray,
    ): Int {
        var completed = false
        try {
            val result =
                guarded {
                    if (offset < 0 || size < 0 || size > data.size) throw ErrnoException("read", OsConstants.EINVAL)
                    runBlocking {
                        val count = (length - offset).coerceAtLeast(0).coerceAtMost(size.toLong()).toInt()
                        var copied = 0
                        while (copied < count) {
                            val amount = minOf(count - copied, 65_536)
                            val bytes = read(offset + copied, amount)
                            if (bytes.size != amount) throw ErrnoException("read", OsConstants.EIO)
                            bytes.copyInto(data, copied)
                            copied += amount
                        }
                        // Includes EOF/zero-byte calls and catches revocation before returning an assembled buffer.
                        read(0, 0)
                        count
                    }
                }
            completed = true
            return result
        } finally {
            if (!completed) data.fill(0)
        }
    }

    override fun onWrite(
        offset: Long,
        size: Int,
        data: ByteArray,
    ): Int = throw ErrnoException("write", OsConstants.EBADF)

    override fun onFsync() = guarded { Unit }

    override fun onRelease() {
        if (closed.compareAndSet(false, true)) release()
    }

    @Suppress("TooGenericExceptionCaught") // Android's syscall boundary requires sanitized errno, not app exceptions.
    private fun <T> guarded(action: () -> T): T {
        try {
            requireOpen()
            val result = action()
            requireOpen()
            return result
        } catch (failure: Exception) {
            onRelease()
            throw when (failure) {
                is CancellationException -> ErrnoException("read", OsConstants.ECANCELED)
                is ErrnoException -> failure
                else -> ErrnoException("read", OsConstants.EIO)
            }
        }
    }

    private fun requireOpen() {
        if (closed.get()) throw ErrnoException("read", OsConstants.EBADF)
    }
}
