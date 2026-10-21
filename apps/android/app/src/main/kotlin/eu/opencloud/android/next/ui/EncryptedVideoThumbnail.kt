package eu.opencloud.android.next.ui

import android.content.Context
import android.graphics.Bitmap
import android.media.MediaMetadataRetriever
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.ParcelFileDescriptor
import android.os.ProxyFileDescriptorCallback
import android.os.storage.StorageManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Extracts a bounded frame through the encrypted, seekable preview backing. */
internal suspend fun loadEncryptedVideoThumbnail(
    context: Context,
    backing: EncryptedPreviewBacking,
): Bitmap? =
    withContext(Dispatchers.IO) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) return@withContext null
        val callbackThread = HandlerThread("encrypted-video-thumbnail").apply { start() }
        val retriever = MediaMetadataRetriever()
        var proxy: ParcelFileDescriptor? = null
        try {
            proxy =
                requireNotNull(context.getSystemService(StorageManager::class.java))
                    .openProxyFileDescriptor(
                        ParcelFileDescriptor.MODE_READ_ONLY,
                        object : ProxyFileDescriptorCallback() {
                            override fun onGetSize(): Long = backing.size

                            override fun onRead(
                                offset: Long,
                                size: Int,
                                data: ByteArray,
                            ): Int =
                                backing.read(
                                    offset,
                                    minOf(size, data.size, MAX_PROXY_READ_BYTES),
                                    data,
                                )

                            override fun onRelease() = Unit
                        },
                        Handler(callbackThread.looper),
                    )
            retriever.setDataSource(requireNotNull(proxy).fileDescriptor)
            retriever.getScaledFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC, 256, 256)
        } finally {
            retriever.release()
            proxy?.close()
            callbackThread.quitSafely()
        }
    }

private const val MAX_PROXY_READ_BYTES = 64 * 1024
