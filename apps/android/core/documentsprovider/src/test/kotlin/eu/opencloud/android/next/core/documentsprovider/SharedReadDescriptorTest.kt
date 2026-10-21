package eu.opencloud.android.next.core.documentsprovider

import android.system.ErrnoException
import android.system.OsConstants
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class SharedReadDescriptorTest {
    @Test fun seeksAndFillsLargeRequestsInBoundedChunks() {
        val bytes = ByteArray(150_000) { (it % 127).toByte() }
        val counts = mutableListOf<Int>()
        val callback =
            SharedReadDescriptor(bytes.size.toLong(), { offset, size ->
                counts.add(size)
                bytes.copyOfRange(offset.toInt(), offset.toInt() + size)
            }, {})
        val output = ByteArray(140_000)
        assertEquals(140_000, callback.onRead(10, output.size, output))
        assertArrayEquals(bytes.copyOfRange(10, 140_010), output)
        assertTrue(counts.all { it <= 65_536 })
        assertEquals(10, callback.onRead(149_990, output.size, output))
        assertEquals(0, callback.onRead(Long.MAX_VALUE, 1, output))
        assertEquals(150_000L, callback.onGetSize())
        callback.onRelease()
    }

    @Test fun failedMultiChunkReadClearsBufferAndClosesOnce() {
        var releases = 0
        val callback =
            SharedReadDescriptor(100_000, { offset, size ->
                if (offset > 0) error("private details must not escape")
                ByteArray(size) { 42 }
            }, { releases++ })
        val data = ByteArray(100_000)
        val error = assertThrows(ErrnoException::class.java) { callback.onRead(0, data.size, data) }
        assertEquals(OsConstants.EIO, error.errno)
        assertTrue(data.all { it == 0.toByte() })
        callback.onRelease()
        assertEquals(1, releases)
        assertEquals(OsConstants.EBADF, assertThrows(ErrnoException::class.java) { callback.onGetSize() }.errno)
    }

    @Test fun cancellationIsNotOrdinaryIoFailure() {
        val callback = SharedReadDescriptor(5, { _, _ -> throw CancellationException() }, {})
        val error = assertThrows(ErrnoException::class.java) { callback.onGetSize() }
        assertEquals(OsConstants.ECANCELED, error.errno)
    }

    @Test fun rejectsWritesInvalidRangesAndPrematureEof() {
        val callback = SharedReadDescriptor(5, { _, _ -> byteArrayOf() }, {})
        assertEquals(
            OsConstants.EBADF,
            assertThrows(ErrnoException::class.java) {
                callback.onWrite(0, 1, byteArrayOf(1))
            }.errno,
        )
        assertEquals(
            OsConstants.EIO,
            assertThrows(ErrnoException::class.java) {
                callback.onRead(0, 5, ByteArray(5))
            }.errno,
        )
        val invalid = SharedReadDescriptor(5, { _, size -> ByteArray(size) }, {})
        assertEquals(
            OsConstants.EINVAL,
            assertThrows(ErrnoException::class.java) {
                invalid.onRead(-1, 1, ByteArray(1))
            }.errno,
        )
    }
}
