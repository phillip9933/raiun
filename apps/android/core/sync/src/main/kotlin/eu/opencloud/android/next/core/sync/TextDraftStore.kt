package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.AtomicFile
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.cacheIdentity
import eu.opencloud.android.next.core.network.DownloadExpectation
import org.json.JSONObject
import java.io.File
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.UUID

/** Drafts are private user data, not temporary cache. Server writes always require the captured version. */
class TextDraftStore(
    private val context: Context,
    private val store: FileBrowserStore = FileBrowserStore(FileBrowserDatabase.create(context)),
) {
    fun discard(draft: TextDraft) {
        require(draft.queuedId == null) { "Finish or cancel the upload before discarding its draft." }
        val saved = file(draft.accountId, draft.spaceId, draft.resourceId)
        saved.delete()
        check(!saved.baseFile.exists()) { "The draft could not be discarded." }
    }

    fun create(
        resource: ResourceEntity,
        file: File,
    ): TextDraft {
        val output = java.io.ByteArrayOutputStream()
        file.inputStream().use { input ->
            val buffer = ByteArray(8192)
            var count = input.read(buffer)
            while (count >= 0) {
                require(output.size() + count <= MAX_TEXT_BYTES)
                output.write(buffer, 0, count)
                count = input.read(buffer)
            }
        }
        return create(resource, output.toByteArray())
    }

    fun read(
        accountId: String,
        spaceId: String,
        resourceId: String,
    ): TextDraft? {
        val file = file(accountId, spaceId, resourceId)
        if (!hasSavedAtomicFile(file)) return null
        val value = JSONObject(readSavedAtomicFile(file, MAX_TEXT_BYTES * 6L + 16_384).toString(Charsets.UTF_8))
        return TextDraft(
            accountId,
            spaceId,
            resourceId,
            value.getString("path"),
            value.getString("name"),
            value.optString("mime").takeIf(String::isNotBlank),
            value.getString("etag"),
            value.getString("text"),
            value.optString("queued").takeIf(String::isNotBlank),
        )
    }

    fun create(
        resource: ResourceEntity,
        bytes: ByteArray,
    ): TextDraft {
        require(bytes.size <= MAX_TEXT_BYTES) { "The editor supports text files up to 256 KB." }
        val eTag =
            requireNotNull(DownloadExpectation(resource.sizeBytes, resource.eTag).strongETag) {
                "The server did not provide a version that can be safely edited."
            }
        val text =
            Charsets.UTF_8
                .newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
        return TextDraft(
            resource.accountId,
            resource.spaceId,
            resource.remoteId,
            resource.path,
            resource.name,
            resource.mimeType,
            eTag,
            text,
        ).also(::save)
    }

    fun save(draft: TextDraft) {
        require(draft.text.toByteArray().size <= MAX_TEXT_BYTES) { "The editor supports text files up to 256 KB." }
        val value =
            JSONObject()
                .put("path", draft.path)
                .put("name", draft.name)
                .put("mime", draft.mimeType)
                .put("etag", draft.baseETag)
                .put("text", draft.text)
                .put("queued", draft.queuedId)
        val file = file(draft.accountId, draft.spaceId, draft.resourceId)
        file.baseFile.parentFile?.mkdirs()
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray())
            file.finishWrite(output)
        } catch (failure: java.io.IOException) {
            file.failWrite(output)
            throw failure
        }
    }

    suspend fun resume(draft: TextDraft): TextDraft {
        val transfer = draft.queuedId?.let { store.transfer(it) }
        val updated =
            when (transfer?.state) {
                "SUCCEEDED" ->
                    DownloadExpectation(0, transfer.verifiedETag).strongETag?.let {
                        // Keep-both saved a different file; retain the original version for subsequent edits.
                        if (transfer.destinationPath != draft.path) return@let draft.copy(queuedId = null)
                        draft.copy(baseETag = it, queuedId = null)
                    } ?: draft
                "CANCELLED" -> draft.copy(queuedId = null)
                null -> draft.copy(queuedId = null)
                else -> draft
            }
        save(updated)
        return updated
    }

    suspend fun submit(draft: TextDraft): TextDraft =
        submit(draft) { source ->
            SharedUploadQueue(context).enqueue(
                draft.accountId,
                draft.spaceId,
                draft.path.substringBeforeLast('/', ""),
                source,
            )
        }

    internal suspend fun submit(
        draft: TextDraft,
        enqueue: suspend (SharedUploadSource) -> Unit,
    ): TextDraft {
        val previous = read(draft.accountId, draft.spaceId, draft.resourceId)
        val reusable = previous?.takeIf { it.copy(queuedId = null) == draft.copy(queuedId = null) }?.queuedId
        val queued = draft.copy(queuedId = draft.queuedId ?: reusable ?: UUID.randomUUID().toString())
        save(queued) // Persist identity first so retrying cannot create a second upload.
        val payload = File(file(draft.accountId, draft.spaceId, draft.resourceId).baseFile.parentFile, "upload.txt")
        payload.writeText(draft.text)
        enqueue(
            SharedUploadSource(
                requireNotNull(queued.queuedId),
                draft.name,
                draft.mimeType,
                payload,
                draft.baseETag,
                draft.resourceId,
            ),
        )
        payload.delete()
        return queued
    }

    private fun file(
        account: String,
        space: String,
        resource: String,
    ): AtomicFile =
        AtomicFile(
            File(
                context.noBackupFilesDir,
                "text-drafts/${cacheIdentity(account)}/${cacheIdentity(space)}/${cacheIdentity(resource)}/draft.json",
            ),
        )

    companion object {
        const val MAX_TEXT_BYTES = 256 * 1024
    }
}
