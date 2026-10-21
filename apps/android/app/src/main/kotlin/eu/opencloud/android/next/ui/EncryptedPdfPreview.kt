package eu.opencloud.android.next.ui

import android.content.Context
import android.graphics.Bitmap
import android.graphics.pdf.PdfRenderer
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import android.system.ErrnoException
import android.system.OsConstants
import androidx.annotation.RequiresApi
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ArrowForward
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.core.content.getSystemService
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudDimensions
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.withContext
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.sqrt
import eu.opencloud.android.next.core.ui.R as UiR

/** In-memory encrypted-content viewer. The caller retains ownership of [pdfBytes]. */
@Composable
fun EncryptedPdfPreview(
    pdfBytes: ByteArray,
    modifier: Modifier = Modifier,
    encryptedBacking: EncryptedPreviewBacking? = null,
) {
    val context = LocalContext.current
    var page by remember(pdfBytes, encryptedBacking) { mutableIntStateOf(0) }
    var document by remember(pdfBytes, encryptedBacking) { mutableStateOf<EncryptedPdfDocument?>(null) }
    var state by remember(pdfBytes, encryptedBacking) { mutableStateOf<EncryptedPdfState>(EncryptedPdfState.Loading) }

    LaunchedEffect(pdfBytes, encryptedBacking) {
        var opened: EncryptedPdfDocument? = null
        var opening: EncryptedPdfDocument? = null
        state = EncryptedPdfState.Loading
        try {
            opened =
                withContext(Dispatchers.IO) {
                    (
                        encryptedBacking?.let { EncryptedPdfDocument.open(context, it) }
                            ?: EncryptedPdfDocument.open(context, pdfBytes)
                    ).also { opening = it }
                }
            document = opened
            awaitCancellation()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            state = EncryptedPdfState.Failed
        } finally {
            document = null
            (opened ?: opening)?.let { withContext(NonCancellable) { it.close() } }
        }
    }

    LaunchedEffect(document, page) {
        val active = document ?: return@LaunchedEffect
        state = EncryptedPdfState.Loading
        var pending: EncryptedPdfPage? = null
        try {
            val rendered = withContext(Dispatchers.IO) { active.render(page).also { pending = it } }
            state = EncryptedPdfState.Ready(rendered)
            pending = null
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            state = EncryptedPdfState.Failed
        } finally {
            pending?.bitmap?.recycle()
        }
    }

    EncryptedPdfPreviewScreen(
        page = page,
        state = state,
        onPage = { page = it },
        modifier = modifier,
    )
}

@Composable
private fun EncryptedPdfPreviewScreen(
    page: Int,
    state: EncryptedPdfState,
    onPage: (Int) -> Unit,
    modifier: Modifier = Modifier,
) {
    val previousLabel = stringResource(UiR.string.encrypted_pdf_previous_page)
    val nextLabel = stringResource(UiR.string.encrypted_pdf_next_page)
    Column(modifier.fillMaxSize()) {
        Box(
            Modifier.weight(1f).fillMaxWidth(),
            contentAlignment = Alignment.Center,
        ) {
            when (state) {
                EncryptedPdfState.Loading -> CircularProgressIndicator()
                EncryptedPdfState.Failed -> Text(stringResource(UiR.string.encrypted_pdf_preview_error))
                is EncryptedPdfState.Ready -> {
                    val bitmap = state.page.bitmap
                    DisposableEffect(bitmap) {
                        onDispose { if (!bitmap.isRecycled) bitmap.recycle() }
                    }
                    Image(
                        bitmap = bitmap.asImageBitmap(),
                        contentDescription = null,
                        modifier = Modifier.fillMaxSize().padding(OpenCloudDimensions.SpacingSm),
                        contentScale = ContentScale.Fit,
                    )
                }
            }
        }
        (state as? EncryptedPdfState.Ready)?.let { ready ->
            Row(
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                IconButton(
                    onClick = { onPage(page - 1) },
                    enabled = page > 0,
                    modifier = Modifier.semantics { contentDescription = previousLabel },
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = null)
                }
                Text(stringResource(UiR.string.encrypted_pdf_page, page + 1, ready.page.pages))
                IconButton(
                    onClick = { onPage(page + 1) },
                    enabled = page + 1 < ready.page.pages,
                    modifier = Modifier.semantics { contentDescription = nextLabel },
                ) {
                    Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null)
                }
            }
        }
    }
}

private sealed interface EncryptedPdfState {
    data object Loading : EncryptedPdfState

    data object Failed : EncryptedPdfState

    data class Ready(
        val page: EncryptedPdfPage,
    ) : EncryptedPdfState
}

internal data class EncryptedPdfPage(
    val bitmap: Bitmap,
    val page: Int,
    val pages: Int,
)

/** Seekable in-memory backing for PdfRenderer. Plaintext is wiped after both owners release it. */
@RequiresApi(Build.VERSION_CODES.O)
internal class EncryptedPdfDocument private constructor(
    private val context: Context,
    private var backing: ByteArray,
    private var encryptedBacking: EncryptedPreviewBacking? = null,
) {
    private val callbackLock = Any()
    private val renderExecutor =
        Executors.newSingleThreadExecutor { runnable ->
            Thread(runnable, "encrypted-pdf-render").apply { isDaemon = true }
        }
    private val renderDispatcher = renderExecutor.asCoroutineDispatcher()
    private val callbackThread = HandlerThread("encrypted-pdf-descriptor").apply { start() }
    private val callbackHandler = Handler(callbackThread.looper)
    private val closeStarted = AtomicBoolean(false)
    private val closeComplete = CompletableDeferred<Unit>()
    private var rendererClosed = false
    private var descriptor: ParcelFileDescriptor? = null
    private var renderer: PdfRenderer? = null

    private val callback =
        object : ProxyFileDescriptorCallback() {
            override fun onGetSize(): Long =
                synchronized(callbackLock) {
                    if (closeStarted.get()) throw ErrnoException("onGetSize", OsConstants.EBADF)
                    encryptedBacking?.size ?: backing.size.toLong()
                }

            override fun onRead(
                offset: Long,
                size: Int,
                data: ByteArray,
            ): Int =
                synchronized(callbackLock) {
                    if (closeStarted.get()) throw ErrnoException("onRead", OsConstants.EBADF)
                    if (offset < 0L || size < 0) throw ErrnoException("onRead", OsConstants.EINVAL)
                    encryptedBacking?.let { return@synchronized it.read(offset, size, data) }
                    if (offset >= backing.size) return@synchronized 0
                    val copied = minOf(size, data.size, backing.size - offset.toInt())
                    System.arraycopy(backing, offset.toInt(), data, 0, copied)
                    copied
                }

            override fun onRelease() {
                synchronized(callbackLock) {
                    wipeBackingWhenSafe()
                }
            }
        }

    // Close the proxy descriptor on any renderer-construction failure, then rethrow.
    @Suppress("TooGenericExceptionCaught")
    private suspend fun initialize() {
        val storageManager = requireNotNull(context.getSystemService<StorageManager>())
        descriptor =
            storageManager.openProxyFileDescriptor(ParcelFileDescriptor.MODE_READ_ONLY, callback, callbackHandler)
        try {
            withContext(renderDispatcher) {
                check(!closeStarted.get())
                val opened = PdfRenderer(requireNotNull(descriptor))
                descriptor = null // PdfRenderer owns the descriptor after successful construction.
                if (opened.pageCount < 1) {
                    opened.close()
                    throw IllegalArgumentException("PDF page count is outside the supported limit.")
                }
                renderer = opened
            }
        } catch (failure: Throwable) {
            runCatching { descriptor?.close() }
            descriptor = null
            throw failure
        }
    }

    // Recycle the bitmap for every render failure, including cancellation/errors.
    @Suppress("TooGenericExceptionCaught")
    suspend fun render(pageIndex: Int): EncryptedPdfPage {
        var pendingBitmap: Bitmap? = null
        try {
            val rendered =
                withContext(renderDispatcher) {
                    check(!closeStarted.get())
                    val active = requireNotNull(renderer)
                    require(pageIndex in 0 until active.pageCount)
                    active.openPage(pageIndex).use { page ->
                        val scale =
                            minOf(
                                MAX_BITMAP_EDGE.toDouble() / page.width,
                                MAX_BITMAP_EDGE.toDouble() / page.height,
                                sqrt(MAX_BITMAP_PIXELS.toDouble() / (page.width.toDouble() * page.height)),
                            )
                        val width = (page.width * scale).toInt().coerceIn(1, MAX_BITMAP_EDGE)
                        val height = (page.height * scale).toInt().coerceIn(1, MAX_BITMAP_EDGE)
                        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                        pendingBitmap = bitmap
                        try {
                            bitmap.eraseColor(OpenCloudColor.DocumentPaper.toArgb())
                            page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            EncryptedPdfPage(bitmap, pageIndex, active.pageCount)
                        } catch (failure: Throwable) {
                            bitmap.recycle()
                            pendingBitmap = null
                            throw failure
                        }
                    }
                }
            pendingBitmap = null
            return rendered
        } finally {
            pendingBitmap?.let { if (!it.isRecycled) it.recycle() }
        }
    }

    // Try every owned-resource close even when a renderer/descriptor close fails.
    @Suppress("TooGenericExceptionCaught")
    suspend fun close() {
        if (!closeStarted.compareAndSet(false, true)) {
            closeComplete.await()
            return
        }
        try {
            withContext(NonCancellable + renderDispatcher) {
                val active = renderer
                renderer = null
                var closeFailure: Throwable? = null
                try {
                    active?.close()
                } catch (failure: Throwable) {
                    closeFailure = failure
                } finally {
                    try {
                        descriptor?.close()
                    } catch (failure: Throwable) {
                        if (closeFailure == null) closeFailure = failure
                    }
                    descriptor = null
                    synchronized(callbackLock) {
                        rendererClosed = true
                        wipeBackingWhenSafe()
                    }
                    callbackThread.quitSafely()
                }
                closeFailure?.let { throw it }
            }
        } finally {
            renderDispatcher.close()
            closeComplete.complete(Unit)
        }
    }

    private fun wipeBackingWhenSafe() {
        if (rendererClosed) {
            backing.fill(0)
            backing = ByteArray(0)
            encryptedBacking = null
        }
    }

    internal fun isBackingCleared(): Boolean =
        synchronized(callbackLock) {
            backing.isEmpty() &&
                encryptedBacking == null
        }

    companion object {
        private const val MAX_BITMAP_EDGE = 2048
        private const val MAX_BITMAP_PIXELS = 4_000_000

        @Suppress("TooGenericExceptionCaught") // Every failure releases the renderer and proxy owners.
        suspend fun open(
            context: Context,
            encryptedBacking: EncryptedPreviewBacking,
        ): EncryptedPdfDocument {
            require(encryptedBacking.size >= 6)
            val signature = ByteArray(5)
            try {
                require(encryptedBacking.read(0, signature.size, signature) == signature.size)
                require(signature.contentEquals(byteArrayOf(37, 80, 68, 70, 45)))
            } finally {
                signature.fill(0)
            }
            val document = EncryptedPdfDocument(context.applicationContext, ByteArray(0), encryptedBacking)
            try {
                document.initialize()
                return document
            } catch (failure: Throwable) {
                document.close()
                throw failure
            }
        }

        @Suppress("TooGenericExceptionCaught") // Ensure descriptor/thread cleanup for every construction failure.
        suspend fun open(
            context: Context,
            pdfBytes: ByteArray,
        ): EncryptedPdfDocument {
            require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            require(pdfBytes.size >= 6)
            require(
                pdfBytes[0] == '%'.code.toByte() &&
                    pdfBytes[1] == 'P'.code.toByte() &&
                    pdfBytes[2] == 'D'.code.toByte() &&
                    pdfBytes[3] == 'F'.code.toByte() &&
                    pdfBytes[4] == '-'.code.toByte(),
            )
            val document = EncryptedPdfDocument(context.applicationContext, pdfBytes.copyOf())
            try {
                document.initialize()
                return document
            } catch (failure: Throwable) {
                withContext(NonCancellable) { document.close() }
                throw failure
            }
        }
    }
}
