package eu.opencloud.android.next.core.sync

import android.content.Context
import android.util.AtomicFile
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** Durable handoff from scanner exports to the normal upload queue. */
class ScanUploadStore private constructor(
    private val context: Context,
    private val enqueue: suspend (ScanUploadLocation, SharedUploadSource) -> Unit,
    @Suppress("UNUSED_PARAMETER") private val constructionMarker: Unit,
) {
    constructor(context: Context) : this(
        context.applicationContext,
        { destination, source ->
            SharedUploadQueue(context.applicationContext).enqueue(
                destination.accountId,
                destination.spaceId,
                destination.parentPath,
                source,
            )
        },
        Unit,
    )

    internal constructor(
        context: Context,
        enqueue: suspend (String, String, String, SharedUploadSource) -> Unit,
    ) : this(
        context.applicationContext,
        { destination, source -> enqueue(destination.accountId, destination.spaceId, destination.parentPath, source) },
        Unit,
    )

    private val root = File(context.noBackupFilesDir, ROOT_DIRECTORY)

    /** Creates a recoverable destination record before the scanner starts exporting. */
    fun create(
        accountId: String,
        spaceId: String,
        parentPath: String,
    ): String {
        require(accountId.isNotBlank() && spaceId.isNotBlank())
        val sessionId = UUID.randomUUID().toString()
        val directory = directory(sessionId).apply { check(mkdirs() || isDirectory) }
        writeJson(
            AtomicFile(File(directory, DESTINATION_FILE)),
            JSONObject()
                .put("account", accountId)
                .put("space", spaceId)
                .put("parent", parentPath),
        )
        return sessionId
    }

    fun location(sessionId: String): ScanUploadLocation =
        requireNotNull(readDestination(directory(sessionId))) { "The scan upload session is unavailable." }

    /** Location stays editable only before export has been committed or queued. */
    suspend fun changeLocation(
        sessionId: String,
        spaceId: String,
        parentPath: String,
    ) = gate(sessionId).withLock {
        require(spaceId.isNotBlank())
        require(parentPath.startsWith('/') && parentPath.split('/').none { it == "." || it == ".." })
        check(!hasCompletedOutput(sessionId)) { "The scan upload destination is already fixed." }
        val current = location(sessionId)
        writeJson(
            AtomicFile(File(directory(sessionId), DESTINATION_FILE)),
            JSONObject().put("account", current.accountId).put("space", spaceId).put("parent", parentPath),
        )
    }

    /** The scanner may write its PDF or JPEG exports directly into this private directory. */
    fun outputDirectory(sessionId: String): File =
        directory(sessionId).apply {
            check(readDestination(this) != null) { "The scan upload session is unavailable." }
            check(mkdirs() || isDirectory)
        }

    /** Publishes an atomic manifest. Repeating this after process death produces the same upload IDs. */
    fun complete(
        sessionId: String,
        files: List<File>,
        mimeType: String,
    ) {
        require(files.isNotEmpty()) { "The scanner did not create any files." }
        require(mimeType.isNotBlank())
        val directory = directory(sessionId)
        val destination = requireNotNull(readDestination(directory)) { "The scan upload session is unavailable." }
        val manifestFile = AtomicFile(File(directory, MANIFEST_FILE))
        val outputs = files.map { validateOutput(directory, it) }
        if (hasSavedAtomicFile(manifestFile)) {
            val saved = readManifest(directory)
            check(
                saved.destination == destination &&
                    saved.entries.map { it.relativePath } == outputs.map { relativePath(directory, it) },
            ) {
                "The scan output has already been recorded."
            }
            check(saved.entries.all { it.mimeType == mimeType }) { "The scan output has already been recorded." }
            return
        }
        require(files.size <= MAX_FILES) { "Too many scanner output files." }
        val names = uniqueNames(outputs)
        val entries =
            outputs.mapIndexed { index, output ->
                require(output.length() > 0L) { "The scanner created an empty file." }
                val relativePath = relativePath(directory, output)
                ScanUploadEntry(
                    id =
                        UUID
                            .nameUUIDFromBytes(
                                "$sessionId:$index:$relativePath".toByteArray(Charsets.UTF_8),
                            ).toString(),
                    name = names[index],
                    relativePath = relativePath,
                    mimeType = mimeType,
                    size = output.length(),
                )
            }
        writeJson(manifestFile, ScanUploadManifest(destination, entries, queued = false).toJson(queued = false))
    }

    /** Idempotently enqueues every recorded file, then releases scanner output bytes. */
    suspend fun submit(sessionId: String) =
        gate(sessionId).withLock {
            val directory = directory(sessionId)
            val saved = readManifest(directory)
            if (!saved.queued) {
                val destination = saved.destination
                saved.entries.forEach { entry ->
                    currentCoroutineContext().ensureActive()
                    val payload = File(directory, entry.relativePath)
                    check(
                        !Files.isSymbolicLink(payload.toPath()) &&
                            payload.isFile &&
                            payload.canonicalFile.parentFile != null &&
                            payload.canonicalFile.toPath().startsWith(directory.canonicalFile.toPath()) &&
                            payload.length() == entry.size,
                    ) {
                        "A scanner output file is unavailable."
                    }
                    enqueue(destination, SharedUploadSource(entry.id, entry.name, entry.mimeType, payload))
                }
                currentCoroutineContext().ensureActive()
                writeJson(AtomicFile(File(directory, MANIFEST_FILE)), saved.toJson(queued = true))
            }
            currentCoroutineContext().ensureActive()
            saved.entries.forEach { entry ->
                val output = File(directory, entry.relativePath)
                if (output.exists()) check(output.delete()) { "Could not clear the scanner output file." }
            }
        }

    fun hasCompletedOutput(sessionId: String): Boolean {
        val directory = directory(sessionId)
        val manifest = AtomicFile(File(directory, MANIFEST_FILE))
        if (!hasSavedAtomicFile(manifest)) recoverCommittedExports(sessionId, directory)
        return hasSavedAtomicFile(manifest) && readManifest(directory).entries.isNotEmpty()
    }

    fun discard(sessionId: String) {
        val directory = directory(sessionId)
        if (directory.exists()) check(directory.deleteRecursively()) { "Could not discard the scanner output." }
    }

    /** Called during account removal after transfer work has been stopped. */
    internal suspend fun clearAccount(accountId: String) {
        if (Files.isSymbolicLink(root.toPath())) return
        root.listFiles().orEmpty().filter(File::isDirectory).forEach { directory ->
            if (Files.isSymbolicLink(directory.toPath())) return@forEach
            val sessionId = runCatching { UUID.fromString(directory.name).toString() }.getOrNull() ?: return@forEach
            gate(sessionId).withLock {
                if (readDestination(directory)?.accountId == accountId) {
                    check(directory.deleteRecursively()) { "Some scanner output files could not be removed." }
                }
            }
        }
    }

    private fun validateOutput(
        directory: File,
        file: File,
    ): File {
        val base = directory.canonicalFile
        val output = file.canonicalFile
        require(
            !Files.isSymbolicLink(file.toPath()) &&
                output != base &&
                output.toPath().startsWith(base.toPath()) &&
                output.isFile,
        ) { "Scanner output must be inside its session directory." }
        val relative = relativePath(directory, output)
        require(relative.split('/').none { it.isBlank() || it == "." || it == ".." || it.startsWith(".pending") }) {
            "Scanner output must be a committed file."
        }
        require(
            output.name.isNotBlank() &&
                output.name !in setOf(".", "..", DESTINATION_FILE, MANIFEST_FILE) &&
                output.name.none { it == '/' || it == '\\' || it.isISOControl() },
        )
        return output
    }

    private fun relativePath(
        directory: File,
        file: File,
    ): String =
        directory.canonicalFile
            .toPath()
            .relativize(
                file.canonicalFile.toPath(),
            ).toString()
            .replace(File.separatorChar, '/')

    private fun uniqueNames(files: List<File>): List<String> {
        val used = mutableSetOf<String>()
        return files.map { file ->
            var name = file.name
            var number = 1
            while (!used.add(name)) {
                name = "${file.nameWithoutExtension} (${number++}).${file.extension}"
            }
            name
        }
    }

    /** The scanner commits exports by atomically renaming scan-UUID directories into place. */
    private fun recoverCommittedExports(
        sessionId: String,
        directory: File,
    ) {
        val outputs =
            directory
                .listFiles()
                .orEmpty()
                .filter { child ->
                    child.isDirectory &&
                        !Files.isSymbolicLink(child.toPath()) &&
                        COMMITTED_EXPORT_DIRECTORY.matches(child.name)
                }.flatMap { exportDirectory ->
                    Files.walk(exportDirectory.toPath()).use { paths ->
                        paths
                            .iterator()
                            .asSequence()
                            .map { it.toFile() }
                            .filter { it.isFile && !Files.isSymbolicLink(it.toPath()) }
                            .toList()
                    }
                }.mapNotNull { file ->
                    val mime =
                        when (file.extension.lowercase()) {
                            "pdf" -> "application/pdf"
                            "jpg", "jpeg" -> "image/jpeg"
                            else -> null
                        }
                    mime?.let { file to it }
                }.sortedBy { relativePath(directory, it.first) }
        if (outputs.isEmpty()) return
        val names = uniqueNames(outputs.map { it.first })
        val entries =
            outputs.mapIndexed { index, (file, mime) ->
                val output = validateOutput(directory, file)
                require(output.length() > 0L) { "The scanner created an empty file." }
                val relative = relativePath(directory, output)
                ScanUploadEntry(
                    UUID.nameUUIDFromBytes("$sessionId:$index:$relative".toByteArray(Charsets.UTF_8)).toString(),
                    names[index],
                    relative,
                    mime,
                    output.length(),
                )
            }
        val destination = requireNotNull(readDestination(directory)) { "The scan upload session is unavailable." }
        writeJson(
            AtomicFile(File(directory, MANIFEST_FILE)),
            ScanUploadManifest(destination, entries, queued = false).toJson(queued = false),
        )
    }

    private fun directory(sessionId: String): File {
        val sessionDirectory = File(root, UUID.fromString(sessionId).toString())
        check(!Files.isSymbolicLink(root.toPath()) && !Files.isSymbolicLink(sessionDirectory.toPath())) {
            "The scan upload session is unavailable."
        }
        if (sessionDirectory.exists()) {
            check(sessionDirectory.canonicalFile.parentFile == root.canonicalFile && sessionDirectory.isDirectory) {
                "The scan upload session is unavailable."
            }
        }
        return sessionDirectory
    }

    private fun readDestination(directory: File): ScanUploadLocation? {
        val file = AtomicFile(File(directory, DESTINATION_FILE))
        if (!hasSavedAtomicFile(file)) return null
        val value = JSONObject(readSavedAtomicFile(file, MAX_MANIFEST_BYTES).toString(Charsets.UTF_8))
        return ScanUploadLocation(value.getString("account"), value.getString("space"), value.getString("parent"))
    }

    private fun readManifest(directory: File): ScanUploadManifest {
        val value =
            JSONObject(
                readSavedAtomicFile(
                    AtomicFile(File(directory, MANIFEST_FILE)),
                    MAX_MANIFEST_BYTES,
                ).toString(Charsets.UTF_8),
            )
        val destination =
            ScanUploadLocation(value.getString("account"), value.getString("space"), value.getString("parent"))
        check(readDestination(directory) == destination) { "The scan upload destination has changed." }
        val array = value.getJSONArray("files")
        require(array.length() in 1..MAX_FILES)
        val entries =
            (0 until array.length()).map { index ->
                val item = array.getJSONObject(index)
                val name = item.getString("name")
                require(
                    name.isNotBlank() &&
                        name !in setOf(".", "..") &&
                        name.none { it == '/' || it == '\\' || it.isISOControl() },
                )
                val relativePath = item.getString("path")
                require(
                    relativePath
                        .split(
                            '/',
                        ).none { it.isBlank() || it == "." || it == ".." || it.startsWith(".pending") },
                )
                check(File(directory, relativePath).canonicalFile.toPath().startsWith(directory.canonicalFile.toPath()))
                ScanUploadEntry(item.getString("id"), name, relativePath, item.getString("mime"), item.getLong("size"))
            }
        require(
            entries.map { it.id }.distinct().size == entries.size &&
                entries.map { it.name }.distinct().size == entries.size,
        )
        return ScanUploadManifest(destination, entries, value.getBoolean("queued"))
    }

    private fun writeJson(
        file: AtomicFile,
        value: JSONObject,
    ) {
        val output = file.startWrite()
        try {
            output.write(value.toString().toByteArray(Charsets.UTF_8))
            file.finishWrite(output)
        } catch (failure: IOException) {
            file.failWrite(output)
            throw failure
        }
    }

    private fun gate(sessionId: String): Mutex = gates.getOrPut(directory(sessionId).absolutePath) { Mutex() }

    private data class ScanUploadEntry(
        val id: String,
        val name: String,
        val relativePath: String,
        val mimeType: String,
        val size: Long,
    )

    private data class ScanUploadManifest(
        val destination: ScanUploadLocation,
        val entries: List<ScanUploadEntry>,
        val queued: Boolean,
    ) {
        fun toJson(queued: Boolean) =
            JSONObject()
                .put("account", destination.accountId)
                .put("space", destination.spaceId)
                .put("parent", destination.parentPath)
                .put("queued", queued)
                .put(
                    "files",
                    JSONArray().apply {
                        entries.forEach { entry ->
                            put(
                                JSONObject()
                                    .put("id", entry.id)
                                    .put("name", entry.name)
                                    .put("path", entry.relativePath)
                                    .put("mime", entry.mimeType)
                                    .put("size", entry.size),
                            )
                        }
                    },
                )
    }

    private companion object {
        const val ROOT_DIRECTORY = "scan-uploads"
        const val DESTINATION_FILE = "destination.json"
        const val MANIFEST_FILE = "manifest.json"
        const val MAX_FILES = 100
        const val MAX_MANIFEST_BYTES = 256 * 1024L
        val COMMITTED_EXPORT_DIRECTORY =
            Regex("scan-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}")
        val gates = ConcurrentHashMap<String, Mutex>()
    }
}

data class ScanUploadLocation(
    val accountId: String,
    val spaceId: String,
    val parentPath: String,
)
