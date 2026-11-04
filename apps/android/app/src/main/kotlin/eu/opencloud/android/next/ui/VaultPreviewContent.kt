package eu.opencloud.android.next.ui

import android.app.Application
import android.graphics.Bitmap
import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream

/** The route retains session/key ownership, generation checks and access-revocation policy. */
internal interface VaultPreviewOwner {
    fun isCurrent(request: VaultPreviewRequest): Boolean

    fun backingAccessValid(request: VaultPreviewRequest): Boolean

    fun isThumbnailCurrent(request: VaultThumbnailRequest): Boolean

    fun reportFailure(
        request: VaultPreviewRequest,
        failure: Exception,
    )
}

/** Owns preview plaintext publication and cleanup; callers retain cancellation and route admission. */
internal class VaultPreviewContent(
    private val application: Application,
    private val ioDispatcher: CoroutineDispatcher,
    private val mutableState: MutableStateFlow<VaultRouteState>,
    private val owner: VaultPreviewOwner,
) {
    var loadedRequest: VaultPreviewRequest? = null
        private set
    private val thumbnailMutex = Mutex()

    fun refreshSource(
        previous: VaultFolder,
        current: VaultFolder,
    ) {
        loadedRequest?.takeIf { it.remoteEntry == previous }?.let {
            loadedRequest = it.copy(remoteEntry = current)
        }
    }

    /** A replacement may already be admitted; another save needs a fresh version. */
    fun forgetRequest() {
        loadedRequest = null
    }

    fun clear() {
        forgetRequest()
        mutableState.value = mutableState.value.copy(previewSaving = false, previewSaveError = null)
        mutableState.value.preview?.let { preview ->
            preview.bytes.fill(0)
            preview.backing?.close()
        }
    }

    // These boundaries expose heterogeneous failures; CancellationException is rethrown explicitly.
    // Early exits reject stale or unsupported previews before publication.
    @Suppress("TooGenericExceptionCaught", "ReturnCount", "CyclomaticComplexMethod")
    suspend fun load(request: VaultPreviewRequest) {
        var bytes: ByteArray? = null
        var backing: EncryptedPreviewBacking? = null
        try {
            val memoryThreshold =
                if (request.kind == VaultPreviewKind.TEXT) {
                    minOf(IN_MEMORY_PREVIEW_BYTES, MAX_VAULT_EDIT_TEXT_BYTES)
                } else {
                    IN_MEMORY_PREVIEW_BYTES
                }
            if (request.remoteEntry.size > memoryThreshold) {
                backing =
                    EncryptedPreviewBacking.create(application) {
                        owner.backingAccessValid(request)
                    }
                request.session.download(request.remoteEntry, backing.outputStream(), Long.MAX_VALUE)
                backing.seal()
                if (!owner.isCurrent(request)) return
                loadedRequest = request
                mutableState.value =
                    mutableState.value.copy(
                        loading = false,
                        error = null,
                        preview =
                            VaultRoutePreview(
                                request.title,
                                ByteArray(0),
                                request.kind,
                                editable =
                                    request.kind == VaultPreviewKind.TEXT &&
                                        !request.session.isOffline &&
                                        request.remoteEntry.strongETag != null,
                                backing = backing,
                            ),
                    )
                backing = null
                return
            }
            bytes = request.session.preview(request.remoteEntry)
            if (
                bytes.size > request.maximumBytes ||
                !owner.isCurrent(request)
            ) {
                bytes.fill(0)
                return
            }
            val kind = request.kind.decodedKind(bytes.size)
            if (kind == VaultPreviewKind.UNSUPPORTED) {
                bytes.fill(0)
                bytes = null
                mutableState.value =
                    mutableState.value.copy(loading = false, error = VaultRouteError.PREVIEW, preview = null)
                return
            }
            loadedRequest = request
            mutableState.value =
                mutableState.value.copy(
                    loading = false,
                    error = null,
                    preview =
                        VaultRoutePreview(
                            request.title,
                            bytes,
                            kind,
                            editable =
                                kind == VaultPreviewKind.TEXT &&
                                    !request.session.isOffline &&
                                    request.remoteEntry.strongETag != null,
                        ),
                )
            bytes = null
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            owner.reportFailure(request, failure)
        } finally {
            bytes?.fill(0)
            backing?.close()
        }
    }

    /** Decoded thumbnails stay in memory and become unusable when their originating lease changes. */
    @Suppress("TooGenericExceptionCaught") // Optional thumbnails must not block directory browsing.
    suspend fun loadThumbnail(request: VaultThumbnailRequest): ByteArray? {
        var bytes: ByteArray? = null
        return try {
            withContext(ioDispatcher) {
                bytes =
                    thumbnailMutex.withLock {
                        if (!owner.isThumbnailCurrent(request)) return@withLock null
                        if (!isVaultVideo(request.entry.route.name) &&
                            request.entry.route.size <= IN_MEMORY_PREVIEW_BYTES
                        ) {
                            return@withLock request.session.preview(request.entry.remote)
                        }
                        streamedThumbnail(request)
                    }
            }
            val ready = bytes
            if (ready != null && ready.size <= MAX_VAULT_IMAGE_BYTES && owner.isThumbnailCurrent(request)) {
                ready.also { bytes = null }
            } else {
                null
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            null
        } finally {
            bytes?.fill(0)
        }
    }

    private suspend fun streamedThumbnail(request: VaultThumbnailRequest): ByteArray? {
        val backing = EncryptedPreviewBacking.create(application) { owner.isThumbnailCurrent(request) }
        return try {
            request.session.download(request.entry.remote, backing.outputStream(), Long.MAX_VALUE)
            backing.seal()
            val bitmap =
                if (isVaultVideo(request.entry.route.name)) {
                    loadEncryptedVideoThumbnail(application, backing)
                } else {
                    decodeBoundedBitmap(backing, maximumDimension = 256)
                }
            bitmap?.let(::encodeThumbnail)
        } finally {
            backing.close()
        }
    }

    private fun encodeThumbnail(bitmap: Bitmap): ByteArray? =
        try {
            ByteArrayOutputStream().use { output ->
                if (bitmap.compress(Bitmap.CompressFormat.PNG, 100, output)) output.toByteArray() else null
            }
        } finally {
            bitmap.recycle()
        }
}

internal data class VaultPreviewRequest(
    val session: VaultRouteSession,
    val account: String,
    val remoteEntry: VaultFolder,
    val title: String,
    val kind: VaultPreviewKind,
    val maximumBytes: Long,
    val token: Long,
)

internal data class VaultThumbnailRequest(
    val session: VaultRouteSession,
    val account: String,
    val token: Long,
    val entry: PresentedVaultFolder,
)

internal fun vaultPreviewKind(name: String): VaultPreviewKind {
    val extension = name.substringAfterLast('.', "").lowercase()
    return when (extension) {
        "txt", "md", "csv", "json", "xml", "yaml", "yml", "log", "ini", "toml" -> VaultPreviewKind.TEXT
        "png", "jpg", "jpeg", "webp", "gif", "bmp", "heic", "heif", "avif" -> VaultPreviewKind.IMAGE
        "pdf" -> VaultPreviewKind.PDF
        else -> VaultPreviewKind.UNSUPPORTED
    }
}

internal fun isVaultVideo(name: String): Boolean =
    name.substringAfterLast('.', "").lowercase(java.util.Locale.ROOT) in
        setOf("mp4", "m4v", "mov", "webm", "mkv", "3gp", "avi", "mpeg", "mpg")

private const val IN_MEMORY_PREVIEW_BYTES = 8 * 1024 * 1024
private const val MAX_VAULT_IMAGE_BYTES = 8 * 1024 * 1024

private fun VaultPreviewKind.decodedKind(size: Int): VaultPreviewKind =
    if (size >= 0) this else VaultPreviewKind.UNSUPPORTED
