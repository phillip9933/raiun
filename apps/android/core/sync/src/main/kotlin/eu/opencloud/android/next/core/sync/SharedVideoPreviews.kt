package eu.opencloud.android.next.core.sync

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.network.TransferClient
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/** Scoped incoming-share previews; the caller never supplies a server URL or authorization header. */
object SharedVideoPreviews {
    private const val MAX_PREVIEW_BYTES = 2 * 1024 * 1024
    private val slots = Semaphore(3)

    suspend fun load(
        context: Context,
        request: SharedDownloadRequest,
    ): Bitmap? =
        withContext(Dispatchers.IO) {
            slots.withPermit { loadAuthorizedPreview(context.applicationContext, request) }
        }

    @Suppress("ReturnCount") // Each early return rejects stale share state, locked access, or a cross-origin URL.
    private suspend fun loadAuthorizedPreview(
        app: Context,
        request: SharedDownloadRequest,
    ): Bitmap? {
        val permit = AppLock(app).beginDocumentRead()
        if (!permit()) return null
        val resolver = SharedDownloadResolver.create(app)
        val prepared = resolver.prepare(request)
        if (!permit()) return null
        val account =
            FileBrowserStore(FileBrowserDatabase.create(app))
                .account(request.accountId)
                ?.takeIf { it.isActive } ?: return null
        if (!sameOrigin(account.serverUrl, prepared.url)) return null
        val authorization = WorkerAuthorizationProvider(app).authorization(account)
        val http =
            TlsPolicy(app).applyTo(
                OkHttpClient
                    .Builder()
                    .followRedirects(false)
                    .followSslRedirects(false)
                    .callTimeout(15, TimeUnit.SECONDS)
                    .build(),
                account.serverUrl,
            )
        authorizeSharedContent(prepared, TransferClient(http), authorization)
        if (!permit() || !resolver.isCurrent(prepared)) return null
        return fetchPreview(http, prepared.url, request.file.eTag, authorization) {
            permit() && resolver.isCurrent(prepared)
        }
    }

    private suspend fun fetchPreview(
        http: OkHttpClient,
        resourceUrl: String,
        eTag: String?,
        authorization: String,
        isCurrent: suspend () -> Boolean,
    ): Bitmap? {
        val call =
            http.newCall(
                Request
                    .Builder()
                    .url(sharedVideoPreviewUrl(resourceUrl, eTag))
                    .header("Authorization", authorization)
                    .build(),
            )
        return withRequestCancellation(call::cancel) {
            call.execute().use { response ->
                if (!response.isSuccessful) return@use null
                val source = response.body?.source() ?: return@use null
                if (source.request(MAX_PREVIEW_BYTES + 1L)) return@use null
                val bytes = source.readByteArray()
                val bitmap = decodePreview(bytes) ?: return@use null
                if (!isCurrent()) {
                    bitmap.recycle()
                    null
                } else {
                    bitmap
                }
            }
        }
    }

    private fun decodePreview(bytes: ByteArray): Bitmap? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        if (bounds.outWidth !in 1..512 || bounds.outHeight !in 1..512) return null
        return BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
    }

    private fun sameOrigin(
        serverUrl: String,
        resourceUrl: String,
    ): Boolean {
        val server = serverUrl.toHttpUrl()
        val resource = resourceUrl.toHttpUrl()
        return server.host == resource.host && server.port == resource.port && server.scheme == resource.scheme
    }
}

internal fun sharedVideoPreviewUrl(
    resourceUrl: String,
    eTag: String?,
): HttpUrl =
    resourceUrl
        .toHttpUrl()
        .newBuilder()
        .addQueryParameter("preview", "1")
        .addQueryParameter("x", "128")
        .addQueryParameter("y", "128")
        .addQueryParameter("a", "1")
        .addQueryParameter("scalingup", "0")
        .apply { eTag?.let { addQueryParameter("c", it.trim('"')) } }
        .build()
