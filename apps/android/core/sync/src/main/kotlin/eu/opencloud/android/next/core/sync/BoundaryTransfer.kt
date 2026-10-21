package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import java.io.InputStream
import java.io.OutputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

@Serializable
data class BoundaryEntry(
    val id: String,
    val path: String,
    val name: String,
    val directory: Boolean,
    val size: Long,
    val version: String?,
    val mimeType: String? = null,
)

/** Implementations bind all access to one account/root and a live authorization or unlock lease. */
interface BoundaryEndpoint {
    val identity: String
    val encrypted: Boolean
    val physicalScope: String get() = identity

    suspend fun physicalPath(path: String): String = path.trim('/')

    suspend fun existingNames(path: String): Set<String> = list(path).map { it.name }.toSet()

    suspend fun list(path: String): List<BoundaryEntry>

    suspend fun requireUnchanged(entry: BoundaryEntry)

    suspend fun read(
        entry: BoundaryEntry,
        sink: OutputStream,
    )

    suspend fun write(
        parent: String,
        name: String,
        source: InputStream,
        size: Long,
        mimeType: String?,
    ): BoundaryEntry

    suspend fun createDirectory(
        parent: String,
        name: String,
    ): BoundaryEntry

    /** Files require the exact source ETag; directories must be empty and conditionally deleted. */
    suspend fun delete(entry: BoundaryEntry)
}

/** A partial move must be inspected; never replay deletion automatically. */
class BoundaryMoveIncompleteException : OpenCloudException(OpenCloudError.PreconditionFailed)

/** Copies plaintext through bounded memory, authenticates readback, then separately authorizes source removal. */
class BoundaryTransfer(
    private val context: Context,
) {
    @Suppress("LongParameterList") // Keep endpoints, source snapshot and destination placement explicit.
    suspend fun execute(
        source: BoundaryEndpoint,
        root: BoundaryEntry,
        destination: BoundaryEndpoint,
        parent: String,
        move: Boolean,
        targetName: String = root.name,
    ) = withContext(Dispatchers.IO) {
        requireBoundaryPlacement(source, root, destination, parent, targetName)
        source.requireUnchanged(root)
        BoundaryManifest(context).use { manifest ->
            val target = copyEntry(source, root, destination, parent, targetName)
            manifest.add(null, root, target)
            while (true) {
                currentCoroutineContext().ensureActive()
                val folder = manifest.nextDirectory() ?: break
                source.requireUnchanged(folder.source)
                source.list(folder.source.path).forEach { entry ->
                    requireDirectChild(folder.source, entry)
                    val copied = copyEntry(source, entry, destination, folder.destination.path)
                    manifest.add(folder.sequence, entry, copied)
                }
            }
            // No source deletion starts until all files verified and the complete source snapshot still matches.
            manifest.forEach { record ->
                currentCoroutineContext().ensureActive()
                source.requireUnchanged(record.source)
                destination.requireUnchanged(record.destination)
                if (record.source.directory) {
                    manifest.requireChildren(record.sequence, source.list(record.source.path))
                    manifest.requireChildren(
                        record.sequence,
                        destination.list(record.destination.path),
                        destination = true,
                    )
                }
            }
            if (move) deleteVerifiedSource(source, destination, manifest)
        }
    }

    private suspend fun copyEntry(
        source: BoundaryEndpoint,
        entry: BoundaryEntry,
        destination: BoundaryEndpoint,
        parent: String,
        targetName: String = entry.name,
    ): BoundaryEntry {
        source.requireUnchanged(entry)
        if (entry.directory) return destination.createDirectory(parent, targetName)
        val (created, fingerprint) = streamCopy(source, entry, destination, parent, targetName)
        val verified = BoundaryDigestSink()
        destination.read(created, verified)
        if (verified.size != fingerprint.size || !MessageDigest.isEqual(verified.digest(), fingerprint.digest())) {
            throw OpenCloudException(OpenCloudError.DownloadIntegrity)
        }
        destination.requireUnchanged(created)
        return created
    }
}

@OptIn(kotlinx.coroutines.InternalCoroutinesApi::class)
@Suppress("TooGenericExceptionCaught") // Close both streams and preserve producer failures on every consumer failure.
private suspend fun streamCopy(
    source: BoundaryEndpoint,
    entry: BoundaryEntry,
    destination: BoundaryEndpoint,
    parent: String,
    targetName: String,
): Pair<BoundaryEntry, BoundaryDigestSink> =
    coroutineScope {
        val output = PipedOutputStream()
        val input = PipedInputStream(output, 64 * 1024)
        val cancellation =
            currentCoroutineContext()[kotlinx.coroutines.Job]!!.invokeOnCompletion(
                onCancelling = true,
                invokeImmediately = true,
            ) { failure ->
                if (failure != null) closeBoundaryPipe(input, output)
            }
        val stopped = AtomicBoolean(false)
        val sourceFailure = AtomicReference<Throwable?>()
        val fingerprint = BoundaryDigestSink(output)
        val producer =
            async(Dispatchers.IO) {
                try {
                    source.read(entry, fingerprint)
                } catch (failure: Exception) {
                    currentCoroutineContext().ensureActive()
                    if (!stopped.get()) sourceFailure.set(failure)
                    throw failure
                } finally {
                    output.close()
                }
            }
        try {
            val created = destination.write(parent, targetName, input, entry.size, entry.mimeType)
            producer.await()
            if (entry.size >= 0 &&
                fingerprint.size != entry.size
            ) {
                throw OpenCloudException(OpenCloudError.PreconditionFailed)
            }
            created to fingerprint
        } catch (failure: Exception) {
            stopped.set(true)
            closeBoundaryPipe(input, output)
            producer.cancel()
            currentCoroutineContext().ensureActive()
            throw sourceFailure.get() ?: failure
        } finally {
            cancellation.dispose()
            closeBoundaryPipe(input, output)
        }
    }

private fun closeBoundaryPipe(
    input: InputStream,
    output: OutputStream,
) {
    runCatching { input.close() }
    runCatching { output.close() }
}

@Suppress("TooGenericExceptionCaught") // A failed cleanup is incomplete, never an automatically retryable move.
private suspend fun deleteVerifiedSource(
    source: BoundaryEndpoint,
    destination: BoundaryEndpoint,
    manifest: BoundaryManifest,
) {
    try {
        manifest.forEach(reverse = true) { record ->
            currentCoroutineContext().ensureActive()
            destination.requireUnchanged(record.destination)
            if (!record.source.directory) source.requireUnchanged(record.source)
            source.delete(record.source)
        }
    } catch (cancelled: kotlinx.coroutines.CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        throw BoundaryMoveIncompleteException()
    }
}

suspend fun requireBoundaryPlacement(
    source: BoundaryEndpoint,
    root: BoundaryEntry,
    destination: BoundaryEndpoint,
    parent: String,
    targetName: String = root.name,
) {
    if (source.physicalScope == destination.physicalScope) {
        val target = destination.physicalPath(childPath(parent, targetName)).trim('/')
        val original = source.physicalPath(root.path).trim('/')
        if (target == original || (root.directory && target.startsWith("$original/"))) {
            throw OpenCloudException(OpenCloudError.PreconditionFailed)
        }
    }
}

private fun requireDirectChild(
    parent: BoundaryEntry,
    child: BoundaryEntry,
) {
    val expected = listOf(parent.path.trim('/'), child.name).filter(String::isNotEmpty).joinToString("/")
    val validName = child.name.isNotBlank() && child.name !in setOf(".", "..")
    val invalidCharacter = child.name.any { it == '/' || it == '\\' || it.isISOControl() }
    if (!validName || invalidCharacter || child.path.trim('/') != expected) {
        throw OpenCloudException(OpenCloudError.InvalidResponse)
    }
}

internal class BoundaryDigestSink(
    private val sink: OutputStream? = null,
) : OutputStream() {
    private val hash = MessageDigest.getInstance("SHA-256")
    var size = 0L
        private set
    private var result: ByteArray? = null

    override fun write(value: Int) {
        write(byteArrayOf(value.toByte()), 0, 1)
    }

    override fun write(
        bytes: ByteArray,
        offset: Int,
        length: Int,
    ) {
        sink?.write(bytes, offset, length)
        hash.update(bytes, offset, length)
        size = Math.addExact(size, length.toLong())
    }

    override fun flush() {
        sink?.flush()
    }

    fun digest(): ByteArray = result ?: hash.digest().also { result = it }
}
