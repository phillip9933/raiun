package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.AtomicFile
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.cacheIdentity
import eu.opencloud.android.next.core.network.DownloadExpectation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Durable writeback journal. Call on an IO dispatcher; provider integration must own the editing descriptor. */
class DocumentEditStore(
    private val context: Context,
) {
    suspend fun begin(
        resource: ResourceEntity,
        original: File,
        reserveWriter: Boolean = false,
        authorized: suspend () -> Boolean = { true },
    ): DocumentEdit =
        gate.withLock {
            check(authorized()) { "Document editing is unavailable or locked." }
            require(resource.kind == ResourceKind.FILE && original.length() == resource.sizeBytes)
            val version = requireNotNull(DownloadExpectation(resource.sizeBytes, resource.eTag).strongETag)
            require(resource.path.substringAfterLast('/') == resource.name.requireValidSegment())
            val edit =
                DocumentEdit(
                    UUID.randomUUID().toString(),
                    resource.accountId,
                    resource.spaceId,
                    resource.remoteId,
                    resource.path,
                    resource.name,
                    resource.mimeType,
                    version,
                )
            check(readRecord(edit) == null) { "An existing edit needs to be finished or recovered first." }
            val directory = directory(edit).apply { check(mkdirs() || isDirectory) }
            check(directory.usableSpace >= original.length()) { "Not enough space for an editable copy." }
            LocalCopyLease.read(original) { copyDurably(original, File(directory, "working")) }
            check(File(directory, "working").length() == resource.sizeBytes) { "The source file changed." }
            save(edit)
            if (reserveWriter) activeWriters.add(edit.id)
            edit
        }

    suspend fun workingFile(edit: DocumentEdit): File =
        gate.withLock {
            check(readRecord(edit) == edit && edit.state == DocumentEditState.OPEN)
            File(directory(edit), "working")
        }

    /** Caller must establish reliable closure and revoke any remaining writers before calling this. */
    suspend fun finish(
        edit: DocumentEdit,
        cleanClose: Boolean,
        authorized: Boolean,
    ): DocumentEdit =
        gate.withLock {
            check(readRecord(edit) == edit && edit.state == DocumentEditState.OPEN)
            val completed =
                if (cleanClose && authorized) {
                    val working = File(directory(edit), "working")
                    check(directory(edit).usableSpace >= working.length()) { "Not enough space to preserve this edit." }
                    val sealed = File(directory(edit), "sealed")
                    copyDurably(working, sealed)
                    edit.copy(
                        state = DocumentEditState.READY,
                        sealedSize = sealed.length(),
                        sealedSha256 = digest(sealed),
                    )
                } else {
                    edit.copy(state = DocumentEditState.REVIEW)
                }
            save(completed)
            activeWriters.remove(edit.id)
            completed
        }

    /** Use after an open/close failure; never promotes incomplete bytes to a submit-ready state. */
    suspend fun requireReview(edit: DocumentEdit): DocumentEdit? =
        gate.withLock {
            val saved = readRecord(edit)
            if (saved == null || saved.id != edit.id) {
                activeWriters.remove(edit.id)
                return@withLock null // Account removal or a stale callback must not recreate private files.
            }
            check(saved.state != DocumentEditState.SUBMITTED)
            saved.copy(state = DocumentEditState.REVIEW).also {
                save(it)
                activeWriters.remove(it.id)
            }
        }

    suspend fun writerActive(edit: DocumentEdit): Boolean = gate.withLock { edit.id in activeWriters }

    /** Account deletion must wait for a draft copy or its staged upload to finish creating private files. */
    internal suspend fun coordinateAccountRemoval(cleanup: () -> Unit) = gate.withLock { cleanup() }

    /** Streams a user-requested recovery copy. The caller owns and closes the output. */
    suspend fun export(
        edit: DocumentEdit,
        output: java.io.OutputStream,
        checkAccess: () -> Unit = {},
    ) = gate.withLock {
        checkAccess()
        val saved = requireNotNull(readRecord(edit))
        check(saved.id == edit.id && saved.id !in activeWriters)
        val payload = File(directory(saved), if (saved.sealedSha256 == null) "working" else "sealed")
        if (saved.sealedSha256 != null) {
            check(payload.length() == saved.sealedSize && digest(payload) == saved.sealedSha256)
        }
        payload.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            var count = input.read(buffer)
            while (count >= 0) {
                currentCoroutineContext().ensureActive()
                checkAccess()
                output.write(buffer, 0, count)
                count = input.read(buffer)
            }
        }
    }

    /** Recovery UI must confirm deletion. Never removes a ready/queued save or an active editing session. */
    suspend fun discard(edit: DocumentEdit) =
        gate.withLock {
            val saved = requireNotNull(readRecord(edit))
            check(saved.id == edit.id && saved.id !in activeWriters)
            check(saved.state == DocumentEditState.OPEN || saved.state == DocumentEditState.REVIEW)
            val directory = directory(saved)
            check(directory.deleteRecursively()) { "The edit could not be discarded." }
        }

    suspend fun pending(accountId: String): List<DocumentEdit> = inventory(accountId).edits

    suspend fun inventory(accountId: String): DocumentEditInventory =
        gate.withLock {
            val root = File(context.noBackupFilesDir, "document-edits/${cacheIdentity(accountId)}")
            var unreadable = 0
            val edits =
                root.listFiles().orEmpty().filter(File::isDirectory).flatMap { space ->
                    space.listFiles().orEmpty().filter(File::isDirectory).mapNotNull { resource ->
                        currentCoroutineContext().ensureActive()
                        runCatching {
                            readManifest(AtomicFile(File(resource, "edit.json")))?.also {
                                check(
                                    it.accountId == accountId && directory(it).canonicalFile == resource.canonicalFile,
                                )
                            }
                        }.onFailure { unreadable++ }.getOrNull()
                    }
                }
            DocumentEditInventory(edits, unreadable)
        }

    /** Call only after observing the corresponding upload as SUCCEEDED or CANCELLED. */
    suspend fun settleSubmission(
        edit: DocumentEdit,
        succeeded: Boolean,
    ) = gate.withLock {
        val saved = readRecord(edit)
        if (saved?.id != edit.id || saved.state != DocumentEditState.SUBMITTED) return@withLock
        check(saved.id !in activeWriters)
        if (succeeded) {
            check(directory(saved).deleteRecursively()) { "The completed draft could not be removed." }
        } else {
            save(saved.copy(state = DocumentEditState.REVIEW))
        }
    }

    suspend fun submit(edit: DocumentEdit): DocumentEdit =
        submit(edit) { saved, source ->
            SharedUploadQueue(context).enqueue(
                saved.accountId,
                saved.spaceId,
                saved.path.substringBeforeLast('/', ""),
                source,
            )
        }

    internal suspend fun submit(
        edit: DocumentEdit,
        enqueue: suspend (DocumentEdit, SharedUploadSource) -> Unit,
    ): DocumentEdit =
        gate.withLock {
            val saved = requireNotNull(readRecord(edit))
            check(saved.id == edit.id)
            check(saved.state == DocumentEditState.READY || saved.state == DocumentEditState.SUBMITTED)
            if (saved.state == DocumentEditState.SUBMITTED) return@withLock saved
            val sealed = File(directory(saved), "sealed")
            check(sealed.length() == saved.sealedSize && digest(sealed) == saved.sealedSha256)
            enqueue(
                saved,
                SharedUploadSource(saved.id, saved.name, saved.mimeType, sealed, saved.baseETag, saved.resourceId),
            )
            saved.copy(state = DocumentEditState.SUBMITTED).also(::save)
        }

    private fun directory(edit: DocumentEdit): File =
        File(
            context.noBackupFilesDir,
            "document-edits/${cacheIdentity(
                edit.accountId,
            )}/${cacheIdentity(edit.spaceId)}/${cacheIdentity(edit.resourceId)}",
        )

    private fun readRecord(edit: DocumentEdit): DocumentEdit? =
        readManifest(AtomicFile(File(directory(edit), "edit.json")))?.also {
            check(it.accountId == edit.accountId && it.spaceId == edit.spaceId && it.resourceId == edit.resourceId)
        }

    private suspend fun copyDurably(
        source: File,
        destination: File,
    ) {
        val atomic = AtomicFile(destination)
        val output = atomic.startWrite()
        var committed = false
        try {
            source.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                var count = input.read(buffer)
                while (count >= 0) {
                    currentCoroutineContext().ensureActive()
                    output.write(buffer, 0, count)
                    count = input.read(buffer)
                }
            }
            atomic.finishWrite(output)
            committed = true
        } finally {
            if (!committed) atomic.failWrite(output)
        }
    }

    private suspend fun digest(file: File): String {
        val hash = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(64 * 1024)
            var count = input.read(buffer)
            while (count >= 0) {
                currentCoroutineContext().ensureActive()
                hash.update(buffer, 0, count)
                count = input.read(buffer)
            }
        }
        return hash.digest().joinToString("") { "%02x".format(it) }
    }

    private fun save(edit: DocumentEdit) {
        val value =
            JSONObject()
                .put("id", edit.id)
                .put("account", edit.accountId)
                .put("space", edit.spaceId)
                .put("resource", edit.resourceId)
                .put("path", edit.path)
                .put("name", edit.name)
                .put("mime", edit.mimeType)
                .put("etag", edit.baseETag)
                .put("state", edit.state.name)
                .put("size", edit.sealedSize)
                .put("sha256", edit.sealedSha256)
        val atomic = AtomicFile(File(directory(edit), "edit.json"))
        val output = atomic.startWrite()
        var committed = false
        try {
            output.write(value.toString().toByteArray(Charsets.UTF_8))
            atomic.finishWrite(output)
            committed = true
        } finally {
            if (!committed) atomic.failWrite(output)
        }
    }

    private fun readManifest(atomic: AtomicFile): DocumentEdit? {
        if (!hasSavedAtomicFile(atomic)) return null
        val value = JSONObject(readSavedAtomicFile(atomic, 64 * 1024).toString(Charsets.UTF_8))
        return DocumentEdit(
            value.getString("id"),
            value.getString("account"),
            value.getString("space"),
            value.getString("resource"),
            value.getString("path"),
            value.getString("name"),
            value.optString("mime").takeIf(String::isNotBlank),
            value.getString("etag"),
            DocumentEditState.valueOf(value.getString("state")),
            value.getLong("size"),
            value.optString("sha256").takeIf(String::isNotBlank),
        )
    }

    private companion object {
        val gate = Mutex()
        val activeWriters = mutableSetOf<String>()
    }
}
