package eu.opencloud.android.next.ui

import android.app.Application
import eu.opencloud.android.next.core.sync.VaultExternalCopyLease
import eu.opencloud.android.next.core.sync.VaultExternalCopyStore
import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayInputStream

/** The lifecycle remains the authority for route/session admission, generation and the operation job. */
internal interface VaultPreviewActionOwner {
    fun isCurrent(
        opened: VaultRouteSession,
        token: Long,
        account: String,
    ): Boolean

    fun nextGeneration(): Long

    fun trackOperation(job: Job)

    suspend fun revalidateSource(
        opened: VaultRouteSession,
        expected: VaultFolder,
    ): VaultFolder

    fun reloadContents(
        opened: VaultRouteSession,
        token: Long,
        account: String,
    )

    fun reportFailure(
        failure: Exception,
        fallback: VaultRouteError,
        context: VaultFailureContext,
    )
}

/**
 * Owns preview action execution, edit buffers and unhanded plaintext leases. It uses the route's
 * operation lifetime; it never acquires, retains independently or replaces a session or key.
 */
internal class VaultPreviewActions(
    private val application: Application,
    private val ioDispatcher: CoroutineDispatcher,
    private val scope: CoroutineScope,
    private val mutableState: MutableStateFlow<VaultRouteState>,
    private val previewContent: VaultPreviewContent,
    private val owner: VaultPreviewActionOwner,
) {
    fun openWith(
        request: VaultExternalHandoffRequest,
        onReady: (VaultExternalCopyLease) -> Unit,
    ) {
        mutableState.value = mutableState.value.copy(loading = true, error = null)
        owner.trackOperation(scope.launch { createExternalHandoff(request, onReady) })
    }

    @Suppress("TooGenericExceptionCaught") // Download, storage and Android launcher failures become safe UI state.
    private suspend fun createExternalHandoff(
        request: VaultExternalHandoffRequest,
        onReady: (VaultExternalCopyLease) -> Unit,
    ) {
        var lease: VaultExternalCopyLease? = null
        try {
            val current = refreshExternalHandoffSource(request) ?: return
            withContext(ioDispatcher) {
                lease =
                    VaultExternalCopyStore.create(
                        application,
                        current.name,
                        eu.opencloud.android.next.core.model
                            .fileMimeType(current.name, current.contentType),
                    ) { sink -> request.session.download(current, sink, Long.MAX_VALUE) }
            }
            if (!owner.isCurrent(request.session, request.token, request.account)) return
            mutableState.value = mutableState.value.copy(loading = false)
            onReady(requireNotNull(lease))
            lease = null // The external-launch owner now cleans up on return or expiry.
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            if (owner.isCurrent(request.session, request.token, request.account)) {
                mutableState.value = mutableState.value.copy(loading = false)
                owner.reportFailure(
                    failure,
                    VaultRouteError.PREVIEW,
                    VaultFailureContext(request.token, request.account, true),
                )
            }
        } finally {
            lease?.cleanup()
        }
    }

    private suspend fun refreshExternalHandoffSource(request: VaultExternalHandoffRequest): VaultFolder? {
        val current = owner.revalidateSource(request.session, request.remote)
        if (!owner.isCurrent(request.session, request.token, request.account)) return null
        previewContent.refreshSource(request.remote, current)
        return current
    }

    @Suppress("TooGenericExceptionCaught") // Server, stream and crypto failures share cancellation-safe cleanup.
    fun saveText(
        preview: VaultRoutePreview,
        bytes: ByteArray,
        offset: Long? = null,
        length: Long = 0,
    ) {
        val request = previewContent.loadedRequest
        val backing = preview.backing
        val rangeValid = validPreviewTextRange(backing, offset, length, bytes.size)
        if (request == null || !canSavePreview(preview, request) || !rangeValid) {
            bytes.fill(0)
            return
        }
        if (!validEditableText(bytes)) {
            bytes.fill(0)
            mutableState.value = mutableState.value.copy(previewSaveError = VaultRouteError.OPERATION)
            return
        }
        val token = owner.nextGeneration()
        mutableState.value = mutableState.value.copy(previewSaving = true, previewSaveError = null)
        val saveJob =
            scope.launch {
                try {
                    withContext(ioDispatcher) {
                        val input =
                            if (offset == null) {
                                ByteArrayInputStream(bytes)
                            } else {
                                EncryptedTextReplacementStream(
                                    requireNotNull(backing).inputStream(),
                                    offset,
                                    length,
                                    bytes,
                                )
                            }
                        input.use {
                            val total =
                                if (offset == null) {
                                    bytes.size.toLong()
                                } else {
                                    requireNotNull(backing).size - length + bytes.size
                                }
                            request.session.queueReplacement(request.remoteEntry, it, total)
                        }
                    }
                    if (!owner.isCurrent(request.session, token, request.account)) return@launch
                    mutableState.value =
                        mutableState.value.copy(queuedUploadCount = mutableState.value.queuedUploadCount + 1)
                    previewContent.clear()
                    mutableState.value = mutableState.value.copy(preview = null, loading = true, error = null)
                    owner.reloadContents(request.session, token, request.account)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (failure: Exception) {
                    if (owner.isCurrent(request.session, token, request.account)) {
                        // Admission may have committed before scheduling/delivery was interrupted.
                        // Retain the draft but require a fresh version before another replacement.
                        previewContent.forgetRequest()
                        mutableState.value =
                            mutableState.value.copy(
                                preview = preview.copy(editable = false),
                                previewSaving = false,
                                previewSaveError = classifyVaultFailure(failure, VaultRouteError.OPERATION),
                            )
                        owner.reportFailure(
                            failure,
                            VaultRouteError.OPERATION,
                            VaultFailureContext(token, request.account, lockOnRevocation = true),
                        )
                    }
                } finally {
                    bytes.fill(0)
                }
            }
        // Also covers cancellation before the launched coroutine has entered its try/finally.
        saveJob.invokeOnCompletion { bytes.fill(0) }
        owner.trackOperation(saveJob)
    }

    private fun validPreviewTextRange(
        backing: EncryptedPreviewBacking?,
        offset: Long?,
        length: Long,
        replacementSize: Int,
    ): Boolean =
        offset == null ||
            runCatching {
                val size = requireNotNull(backing).size
                offset >= 0 &&
                    length >= 0 &&
                    offset <= size &&
                    length <= size - offset &&
                    replacementSize.toLong() <= Long.MAX_VALUE - (size - length)
            }.getOrDefault(false)

    private fun canSavePreview(
        preview: VaultRoutePreview,
        request: VaultPreviewRequest,
    ): Boolean =
        mutableState.value.mode == VaultRouteMode.CONTENTS &&
            !mutableState.value.loading &&
            !mutableState.value.previewSaving &&
            mutableState.value.preview === preview &&
            preview.editable &&
            preview.kind == VaultPreviewKind.TEXT &&
            !request.session.isOffline &&
            owner.isCurrent(request.session, request.token, request.account)
}

internal data class VaultExternalHandoffRequest(
    val session: VaultRouteSession,
    val account: String,
    val remote: VaultFolder,
    val token: Long,
)
