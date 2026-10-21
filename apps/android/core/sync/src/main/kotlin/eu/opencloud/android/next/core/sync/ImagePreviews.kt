package eu.opencloud.android.next.core.sync

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.media.MediaMetadataRetriever
import android.os.Build
import android.util.LruCache
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.model.validatedCachedFile
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/** Small image and video previews; never fall back to downloading full cloud files for a thumbnail. */
object ImagePreviews {
    private val slots = Semaphore(3)
    private val cache =
        object : LruCache<String, Bitmap>(4 * 1024 * 1024) {
            override fun sizeOf(
                key: String,
                value: Bitmap,
            ): Int = value.allocationByteCount
        }

    suspend fun load(
        context: Context,
        resource: ResourceEntity,
    ): Bitmap? =
        withContext(Dispatchers.IO) {
            slots.withPermit {
                val store = FileBrowserStore(FileBrowserDatabase.create(context))
                val account = store.account(resource.accountId)?.takeIf { it.isActive } ?: return@withPermit null
                val space =
                    store.space(resource.accountId, resource.spaceId)?.takeUnless { it.isDeleted || it.isDisabled }
                        ?: return@withPermit null
                val key =
                    listOf(
                        resource.accountId,
                        resource.spaceId,
                        resource.remoteId,
                        resource.eTag,
                        resource.modifiedAtEpochMillis.toString(),
                        resource.sizeBytes.toString(),
                    ).joinToString("\u0000")
                cache.get(key)?.let { return@withPermit it }
                val local =
                    if (resource.hasLocalCopy) {
                        validatedCachedFile(
                            resourceCacheDirectory(context.filesDir, resource.accountId, resource.spaceId),
                            resource.localPath,
                            resource.sizeBytes,
                        )
                    } else {
                        null
                    }
                val bitmap =
                    if (local != null) {
                        LocalCopyLease.read(local) {
                            if (resource.isVideoPreview()) {
                                loadLocalVideoFrame(
                                    local.path,
                                )
                            } else {
                                loadLocalImage(local.path)
                            }
                        }
                    } else {
                        loadCloudPreview(context, resource, space, account)
                    }
                bitmap?.also { cache.put(key, it) }
            }
        }

    private suspend fun loadCloudPreview(
        context: Context,
        resource: ResourceEntity,
        space: eu.opencloud.android.next.core.database.SpaceEntity,
        account: eu.opencloud.android.next.core.database.AccountEntity,
    ): Bitmap? {
        val root = webDavRoot(space).toHttpUrl()
        val server = account.serverUrl.toHttpUrl()
        if (root.host != server.host ||
            root.port != server.port ||
            root.scheme != server.scheme
        ) {
            return null
        }
        val url = previewUrl(root, resource)
        val authorization = WorkerAuthorizationProvider(context).authorization(account)
        val client =
            TlsPolicy(context).applyTo(
                OkHttpClient
                    .Builder()
                    .followRedirects(false)
                    .followSslRedirects(false)
                    .callTimeout(15, TimeUnit.SECONDS)
                    .build(),
                account.serverUrl,
            )
        val call =
            client.newCall(
                Request
                    .Builder()
                    .url(url)
                    .header("Authorization", authorization)
                    .build(),
            )
        return withRequestCancellation(call::cancel) {
            call.execute().use { response ->
                if (!response.isSuccessful) return@use null
                val source = response.body?.source() ?: return@use null
                if (source.request(2L * 1024 * 1024 + 1)) return@use null
                val bytes = source.readByteArray()
                val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                if (bounds.outWidth !in 1..512 || bounds.outHeight !in 1..512) return@use null
                BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
            }
        }
    }

    private fun loadLocalImage(path: String): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeFile(path, bounds)
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null
        val options =
            BitmapFactory.Options().apply {
                inSampleSize = sampleSize(bounds.outWidth, bounds.outHeight)
            }
        return BitmapFactory.decodeFile(path, options)
    }

    /** API 27+ can request a scaled frame without materializing the source frame at full resolution. */
    private fun loadLocalVideoFrame(path: String): Bitmap? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O_MR1) return null
        val retriever = MediaMetadataRetriever()
        return try {
            retriever.setDataSource(path)
            retriever.getScaledFrameAtTime(0, MediaMetadataRetriever.OPTION_CLOSEST_SYNC, 256, 256)
        } finally {
            retriever.release()
        }
    }

    private fun previewUrl(
        root: okhttp3.HttpUrl,
        resource: ResourceEntity,
    ): okhttp3.HttpUrl =
        root
            .newBuilder()
            .apply {
                resource.path.trim('/').split('/').filter(String::isNotBlank).forEach { segment ->
                    require(segment != "." && segment != ".." && '\\' !in segment)
                    addPathSegment(segment)
                }
                addQueryParameter("preview", "1")
                addQueryParameter("x", "128")
                addQueryParameter("y", "128")
                addQueryParameter("a", "1")
                addQueryParameter("scalingup", "0")
                resource.eTag?.let { addQueryParameter("c", it.trim('"')) }
            }.build()

    private fun sampleSize(
        width: Int,
        height: Int,
    ): Int {
        var sample = 1
        while (maxOf(width, height) / sample > 256) sample *= 2
        return sample
    }
}

fun ResourceEntity.isVideoPreview(): Boolean =
    mimeType?.substringBefore(';')?.startsWith("video/", ignoreCase = true) == true ||
        name.substringAfterLast('.', "").lowercase() in
        setOf("3gp", "avi", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "webm")
