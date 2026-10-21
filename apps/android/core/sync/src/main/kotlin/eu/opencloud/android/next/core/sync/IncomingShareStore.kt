package eu.opencloud.android.next.core.sync

import android.content.Context
import android.net.Uri
import android.os.CancellationSignal
import android.provider.OpenableColumns
import android.system.StructPollfd
import android.util.AtomicFile
import android.webkit.MimeTypeMap
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.InputStream
import java.util.Locale
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/** Private, durable intake while the user chooses a destination. Never interprets shared file contents. */
class IncomingShareStore(
    private val context: Context,
    private val availableBytes: (File) -> Long = { it.usableSpace },
    private val pollReady: (StructPollfd, Int) -> Boolean = { descriptor, timeout ->
        android.system.Os.poll(arrayOf(descriptor), timeout) > 0
    },
) {
    private val root = File(context.noBackupFilesDir, "incoming-shares")

    fun isStaged(batchId: String): Boolean = hasSavedAtomicFile(AtomicFile(File(directory(batchId), "manifest.json")))

    fun destination(batchId: String): IncomingShareDestination? {
        val file = AtomicFile(File(directory(batchId), "destination.json"))
        if (!hasSavedAtomicFile(file)) return null
        val value = JSONObject(readSavedAtomicFile(file, 16_384).toString(Charsets.UTF_8))
        return IncomingShareDestination(value.getString("account"), value.getString("space"), value.getString("parent"))
    }

    internal fun rememberDestination(
        batchId: String,
        destination: IncomingShareDestination,
    ) {
        check(isStaged(batchId)) { "The shared files are unavailable." }
        val previous = this.destination(batchId)
        check(previous == null || previous == destination) { "Keep the original upload destination when retrying." }
        val file = AtomicFile(File(directory(batchId), "destination.json"))
        val value =
            JSONObject()
                .put("account", destination.accountId)
                .put("space", destination.spaceId)
                .put("parent", destination.parentPath)
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray(Charsets.UTF_8))
            file.finishWrite(output)
        } catch (failure: java.io.IOException) {
            file.failWrite(output)
            throw failure
        }
    }

    @OptIn(InternalCoroutinesApi::class)
    @Suppress("TooGenericExceptionCaught") // Any failed intake must remove unaccepted partial bytes.
    suspend fun stage(
        batchId: String,
        sources: List<Uri>,
        checkActive: () -> Unit,
    ): List<SharedUploadSource> =
        batchGate(batchId).withLock {
            checkActive()
            val job = currentCoroutineContext()[Job]
            val batch = directory(batchId)
            val files =
                (0 until 100).flatMap { uploadSourceFiles(File(batch, it.toString())) } +
                    listOf("manifest.json", "manifest.json.bak", "manifest.json.new").map { File(batch, it) }
            PrivateCacheUse.hold(files) {
                try {
                    stageBatch(batchId, sources, checkActive, job)
                } catch (failure: Throwable) {
                    // Only an accepted, destination-bound batch may survive a failed attempt.
                    if (runCatching { destination(batchId) }.getOrNull() == null) removeBatch(batchId)
                    throw failure
                }
            }
        }

    private fun stageBatch(
        batchId: String,
        sources: List<Uri>,
        checkActive: () -> Unit,
        job: Job?,
    ): List<SharedUploadSource> {
        val directory = directory(batchId)
        val manifest = AtomicFile(File(directory, "manifest.json"))
        if (hasSavedAtomicFile(manifest)) return read(directory, manifest)
        require(sources.isNotEmpty() && sources.size <= 100) { "Choose between 1 and 100 files." }
        directory.mkdirs()
        val signal = CancellationSignal()
        val stopped = AtomicBoolean(false)
        val opened = AtomicReference<InputStream?>()
        val stop: () -> Unit = {
            stopped.set(true)
            runCatching { opened.getAndSet(null)?.close() }
            signal.cancel()
        }

        @OptIn(InternalCoroutinesApi::class)
        val cancellation = job?.invokeOnCompletion(onCancelling = true, invokeImmediately = true) { stop() }
        val deadline = AtomicReference<ScheduledFuture<*>?>()
        val armDeadline: () -> Unit = {
            deadline.getAndSet(watchdog.schedule(stop, 60, TimeUnit.SECONDS))?.cancel(false)
        }
        val clearDeadline: () -> Unit = { deadline.getAndSet(null)?.cancel(false) }
        try {
            armDeadline()
            return stageOpenedBatch(
                batchId,
                sources,
                checkActive,
                directory,
                manifest,
                signal,
                stopped,
                opened,
                armDeadline,
                clearDeadline,
            )
        } finally {
            clearDeadline()
            cancellation?.dispose()
            opened.getAndSet(null)?.close()
        }
    }

    // The guarded batch owns distinct I/O, cancellation, and storage failures.
    @Suppress("LongParameterList", "ThrowsCount")
    private fun stageOpenedBatch(
        batchId: String,
        sources: List<Uri>,
        checkActive: () -> Unit,
        directory: File,
        manifest: AtomicFile,
        signal: CancellationSignal,
        stopped: AtomicBoolean,
        opened: AtomicReference<InputStream?>,
        armDeadline: () -> Unit,
        clearDeadline: () -> Unit,
    ): List<SharedUploadSource> {
        val entries = JSONArray()
        val initialFree = availableBytes(directory)
        val reserve = maxOf(256L * 1024 * 1024, initialFree / 10)
        val stagingBudget = (initialFree - reserve).coerceAtLeast(0) / 2
        if (stagingBudget == 0L) {
            throw eu.opencloud.android.next.core.network.OpenCloudException(
                eu.opencloud.android.next.core.network.OpenCloudError.LocalStorage,
            )
        }
        var stagedBytes = 0L
        sources.forEachIndexed { index, uri ->
            checkActive()
            armDeadline()
            require(uri.scheme == "content" && uri.authority != "${context.packageName}.documents") {
                "Share readable files from another app."
            }
            val name = displayName(uri, signal)
            val remaining = stagingBudget - stagedBytes
            val target = File(directory, index.toString())
            val file =
                stageUploadSource(
                    target,
                    -1,
                    {
                        openIncomingUploadSource(
                            context,
                            uri,
                            signal,
                            { stopped.get() },
                            pollReady,
                        ).also { opened.set(it) }
                    },
                    { availableBytes(directory) - stagedBytes - File(target, "partial").length() },
                    minimumFreeBytes = reserve,
                    maximumBytes = remaining,
                    onReadStart = armDeadline,
                    onReadEnd = clearDeadline,
                    checkActive = {
                        checkActive()
                        if (signal.isCanceled) throw java.io.IOException("The shared source stopped responding.")
                    },
                )
            opened.set(null)
            stagedBytes += file.length()
            entries.put(
                JSONObject()
                    .put("id", UUID.nameUUIDFromBytes("$batchId:$index".toByteArray()).toString())
                    .put("name", name)
                    .put(
                        "mime",
                        MimeTypeMap.getSingleton().getMimeTypeFromExtension(
                            name.substringAfterLast('.', "").lowercase(Locale.ROOT),
                        ),
                    ).put("index", index)
                    .put("size", file.length()),
            )
        }
        val output = manifest.startWrite()
        var finished = false
        try {
            checkActive()
            output.write(entries.toString().toByteArray(Charsets.UTF_8))
            manifest.finishWrite(output)
            finished = true
            checkActive()
            if (signal.isCanceled) throw java.io.IOException("The shared source stopped responding.")
        } catch (failure: java.io.IOException) {
            if (!finished) manifest.failWrite(output)
            throw failure
        }
        return read(directory, manifest)
    }

    suspend fun submit(
        batchId: String,
        destination: IncomingShareDestination,
        enqueue: suspend (SharedUploadSource) -> Unit,
    ) = batchGate(batchId).withLock {
        val batch = directory(batchId)
        val files = read(batch, AtomicFile(File(batch, "manifest.json")))
        rememberDestination(batchId, destination)
        files.forEach {
            currentCoroutineContext().ensureActive()
            enqueue(it)
        }
        currentCoroutineContext().ensureActive()
        removeBatch(batchId)
    }

    suspend fun discard(batchId: String) = batchGate(batchId).withLock { removeBatch(batchId) }

    private fun removeBatch(batchId: String) {
        val batch = directory(batchId)
        check(!batch.exists() || batch.deleteRecursively()) { "Could not clear the incoming files." }
    }

    private fun batchGate(batchId: String): Mutex = gates.getOrPut(directory(batchId).absolutePath) { Mutex() }

    private companion object {
        val gates = ConcurrentHashMap<String, Mutex>()
        val watchdog =
            ScheduledThreadPoolExecutor(1) { work ->
                Thread(work, "incoming-share-deadline").apply { isDaemon = true }
            }.apply { removeOnCancelPolicy = true }
    }

    private fun directory(batchId: String): File = File(root, UUID.fromString(batchId).toString())

    private fun read(
        directory: File,
        manifest: AtomicFile,
    ): List<SharedUploadSource> {
        val entries = JSONArray(readSavedAtomicFile(manifest, 128 * 1024L).toString(Charsets.UTF_8))
        require(entries.length() in 1..100)
        return (0 until entries.length())
            .map { index ->
                val item = entries.getJSONObject(index)
                val payload = File(directory, "$index/payload")
                check(payload.isFile && payload.length() == item.getLong("size")) { "Share the files again to retry." }
                payload.setLastModified(System.currentTimeMillis())
                File(directory, "$index/seal").setLastModified(System.currentTimeMillis())
                SharedUploadSource(
                    item.getString("id"),
                    item.getString("name"),
                    item.optString("mime").takeIf(String::isNotBlank),
                    payload,
                )
            }.also { manifest.baseFile.setLastModified(System.currentTimeMillis()) }
    }

    private fun displayName(
        uri: Uri,
        signal: CancellationSignal,
    ): String {
        val name =
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null, signal)?.use {
                val column = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (column >= 0 && it.moveToFirst() && !it.isNull(column)) it.getString(column) else null
            } ?: uri.lastPathSegment?.substringAfterLast('/') ?: "shared-file"
        require(name.isNotBlank() && name.length <= 255 && name !in setOf(".", "..")) { "Invalid shared filename." }
        require(name.none { it == '/' || it == '\\' || it.isISOControl() }) { "Invalid shared filename." }
        return name
    }
}

data class IncomingShareDestination(
    val accountId: String,
    val spaceId: String,
    val parentPath: String,
)
