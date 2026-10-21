package eu.opencloud.android.next.core.documentsprovider

import android.os.CancellationSignal
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.DocumentEdit
import eu.opencloud.android.next.core.sync.DocumentEditStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/** Seekable private editing descriptor; only a clean, authorized close may queue a sealed upload. */
internal class DocumentWriteSession(
    private val drafts: DocumentEditStore,
    private val scope: CoroutineScope,
    private val authorized: suspend () -> Boolean,
    private val submit: suspend (DocumentEdit) -> Unit = { drafts.submit(it) },
    private val openDescriptor: (File, Int, (IOException?) -> Unit) -> ParcelFileDescriptor = { file, mode, closed ->
        ParcelFileDescriptor.open(file, mode, Handler(Looper.getMainLooper()), closed)
    },
) {
    suspend fun open(
        resource: ResourceEntity,
        original: File,
        mode: String,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        val access = writeAccessMode(mode)
        signal?.throwIfCanceled()
        check(authorized()) { "Document editing is unavailable or locked." }
        val edit = drafts.begin(resource, original, reserveWriter = true, authorized = authorized)
        return openReserved(edit, access, signal)
    }

    // Any failed open must relinquish its reserved writer while retaining recoverable bytes.
    @Suppress("TooGenericExceptionCaught")
    private suspend fun openReserved(
        edit: DocumentEdit,
        access: Int,
        signal: CancellationSignal?,
    ): ParcelFileDescriptor {
        val cancelled = AtomicBoolean(false)
        val closed = AtomicBoolean(false)
        try {
            signal?.throwIfCanceled()
            check(authorized()) { "Document editing is unavailable or locked." }
            signal?.setOnCancelListener { cancelled.set(true) }
            signal?.throwIfCanceled()
            return openDescriptor(drafts.workingFile(edit), access) { error ->
                if (closed.compareAndSet(false, true)) {
                    scope.launch(Dispatchers.IO) {
                        complete(edit, error == null && !cancelled.get())
                    }
                }
            }
        } catch (failure: Exception) {
            preserveFailure(edit, failure)
            throw failure
        }
    }

    // Failed callbacks retain their journal for recovery; cancellation must keep its original type.
    @Suppress("TooGenericExceptionCaught")
    private suspend fun complete(
        edit: DocumentEdit,
        clean: Boolean,
    ) {
        try {
            val allowed = clean && authorized()
            val ready = drafts.finish(edit, cleanClose = clean, authorized = allowed)
            if (allowed) {
                if (authorized()) submit(ready) else drafts.requireReview(ready)
            }
        } catch (cancelled: CancellationException) {
            preserveFailure(edit, cancelled)
            throw cancelled
        } catch (failure: Exception) {
            preserveFailure(edit, failure)
        }
    }

    @Suppress("TooGenericExceptionCaught") // Cleanup must not replace cancellation or the original open failure.
    private suspend fun preserveFailure(edit: DocumentEdit, failure: Exception) {
        withContext(NonCancellable) {
            try {
                retainForReview(edit)
            } catch (cleanup: Exception) {
                failure.addSuppressed(cleanup)
            }
        }
    }

    private suspend fun retainForReview(edit: DocumentEdit) {
        // Only unfinished writes need demotion. A sealed READY save retains its retry identity.
        if (drafts.writerActive(edit)) drafts.requireReview(edit)
    }
}

internal fun writeAccessMode(mode: String): Int =
    when (mode) {
        "w", "wt" -> ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_TRUNCATE
        "wa" -> ParcelFileDescriptor.MODE_WRITE_ONLY or ParcelFileDescriptor.MODE_APPEND
        "rw" -> ParcelFileDescriptor.MODE_READ_WRITE
        "rwt" -> ParcelFileDescriptor.MODE_READ_WRITE or ParcelFileDescriptor.MODE_TRUNCATE
        else -> throw UnsupportedOperationException("Unsupported document write mode.")
    }
