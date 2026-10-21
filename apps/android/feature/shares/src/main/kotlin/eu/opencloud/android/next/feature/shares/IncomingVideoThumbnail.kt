package eu.opencloud.android.next.feature.shares

import android.content.Context
import android.graphics.Bitmap
import android.media.MediaMetadataRetriever
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import eu.opencloud.android.next.core.sync.SharedLocalReader
import eu.opencloud.android.next.core.sync.SharedVideoPreviews
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import java.io.IOException

/** Reads only authenticated, bounded ranges from the scoped local-copy lease. No plaintext file is created. */
internal suspend fun loadIncomingVideoThumbnail(
    context: Context,
    request: SharedDownloadRequest,
    hasLocalCopy: Boolean,
): Bitmap? =
    withContext(Dispatchers.IO) {
        val serverPreview =
            try {
                SharedVideoPreviews.load(context, request)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                null
            }
        if (serverPreview != null || !hasLocalCopy) return@withContext serverPreview
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) return@withContext null
        val session = SharedLocalReader.open(context, request)
        val callbackThread = HandlerThread("shared-video-thumbnail").apply { start() }
        val proxy =
            try {
                requireNotNull(context.getSystemService(StorageManager::class.java))
                    .openProxyFileDescriptor(
                        ParcelFileDescriptor.MODE_READ_ONLY,
                        object : ProxyFileDescriptorCallback() {
                            override fun onGetSize(): Long = session.size

                            override fun onRead(
                                offset: Long,
                                size: Int,
                                data: ByteArray,
                            ): Int =
                                if (offset >= session.size) {
                                    0
                                } else {
                                    val count =
                                        minOf(
                                            size,
                                            data.size,
                                            MAX_PROXY_READ_BYTES,
                                            (session.size - offset).coerceAtMost(MAX_PROXY_READ_BYTES.toLong()).toInt(),
                                        )
                                    if (count <= 0) {
                                        0
                                    } else {
                                        val bytes = runBlocking { session.read(offset, count) }
                                        try {
                                            bytes.copyInto(data, endIndex = minOf(bytes.size, data.size))
                                            minOf(bytes.size, data.size)
                                        } finally {
                                            bytes.fill(0)
                                        }
                                    }
                                }

                            override fun onRelease() = session.close()
                        },
                        Handler(callbackThread.looper),
                    )
            } catch (failure: IOException) {
                callbackThread.quitSafely()
                session.close()
                throw failure
            }
        val retriever = MediaMetadataRetriever()
        try {
            retriever.setDataSource(proxy.fileDescriptor)
            retriever.getScaledFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC, 256, 256)
        } finally {
            retriever.release()
            proxy.close()
            session.close()
            callbackThread.quitSafely()
        }
    }

private const val MAX_PROXY_READ_BYTES = 64 * 1024
