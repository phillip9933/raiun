package eu.opencloud.android.next.core.documentsprovider

import android.content.Context
import android.os.CancellationSignal
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.storage.StorageManager
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import eu.opencloud.android.next.core.sync.SharedReadPreparation
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.job
import kotlinx.coroutines.withContext
import java.io.FileNotFoundException
import java.util.concurrent.Semaphore

internal class SharedReadSource(
    val size: Long,
    val read: suspend (Long, Int) -> ByteArray,
    val close: () -> Unit,
)

/** Admission covers opening and the live reader; failed, cancelled and released opens relinquish it once. */
internal class SharedDocumentReads(
    private val prepare: suspend (SharedDownloadRequest) -> SharedReadSource,
    private val openDescriptor: (SharedReadDescriptor) -> ParcelFileDescriptor,
    private val slots: Semaphore = Semaphore(8),
) {
    suspend fun open(
        request: SharedDownloadRequest,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        signal?.throwIfCanceled()
        if (!slots.tryAcquire()) throw FileNotFoundException("Too many shared documents are open.")
        val reservation = ReadReservation { slots.release() }
        var descriptor: ParcelFileDescriptor? = null
        var delivered = false
        try {
            val result =
                withContext(Dispatchers.IO) {
                    val job = currentCoroutineContext().job
                    signal?.setOnCancelListener {
                        job.cancel(CancellationException("Document opening cancelled."))
                        reservation.revoke()
                    }
                    currentCoroutineContext().ensureActive()
                    val source = prepare(request)
                    reservation.attach(source)
                    val callback = SharedReadDescriptor(source.size, source.read, reservation::close)
                    val opened = openDescriptor(callback)
                    descriptor = opened
                    currentCoroutineContext().ensureActive()
                    signal?.throwIfCanceled()
                    opened
                }
            delivered = true
            return result
        } finally {
            if (!delivered) {
                try {
                    descriptor?.close()
                } finally {
                    reservation.close()
                }
            }
        }
    }

    companion object {
        private val handler by lazy {
            Handler(HandlerThread("shared-document-reads").apply { start() }.looper)
        }
        private val sharedSlots = Semaphore(8)

        fun create(context: Context): SharedDocumentReads {
            val app = context.applicationContext
            return SharedDocumentReads(
                { request ->
                    val session = SharedReadPreparation.open(app, request)
                    SharedReadSource(session.size, session::read, session::close)
                },
                { callback ->
                    app.getSystemService(StorageManager::class.java).openProxyFileDescriptor(
                        ParcelFileDescriptor.MODE_READ_ONLY,
                        callback,
                        handler,
                    )
                },
                sharedSlots,
            )
        }
    }
}

private class ReadReservation(
    private val releaseSlot: () -> Unit,
) {
    private var closed = false
    private var revoked = false
    private var source: SharedReadSource? = null

    @Synchronized
    fun attach(value: SharedReadSource) {
        if (closed || revoked) {
            value.close()
            throw CancellationException("Document opening cancelled.")
        }
        source = value
    }

    @Synchronized
    fun revoke() {
        revoked = true
        closeSource()
    }

    private fun closeSource() {
        val previous = source
        source = null
        previous?.close?.invoke()
    }

    @Synchronized
    fun close() {
        if (!closed) {
            closed = true
            try {
                closeSource()
            } finally {
                releaseSlot()
            }
        }
    }
}
