package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

internal const val BOUNDARY_DIRECTORY_BYTES = 1024 * 1024
internal const val BOUNDARY_DIRECTORY_PAGE = 128

internal fun invalidBoundaryDirectory(): Nothing = throw OpenCloudException(OpenCloudError.InvalidResponse)

internal fun requireBoundaryDirectoryChild(
    parent: String,
    entry: BoundaryEntry,
) {
    if (listOf(parent, entry.path, entry.name, entry.id).any { it.length > BOUNDARY_DIRECTORY_BYTES }) {
        boundaryDirectoryTooLarge()
    }
    val validName = entry.name.isNotBlank() && entry.name !in setOf(".", "..")
    val invalidCharacter = entry.name.any { it == '/' || it == '\\' || it.isISOControl() }
    if (!validName || invalidCharacter) invalidBoundaryDirectory()
    val canonical = entry.path.trim('/')
    val expected = listOf(parent.trim('/'), entry.name).filter(String::isNotEmpty).joinToString("/")
    if (entry.id.isBlank() || entry.size < 0 || canonical != expected) invalidBoundaryDirectory()
}

internal fun requireBoundaryDirectoryParent(path: String) {
    if (path.length > BOUNDARY_DIRECTORY_BYTES) boundaryDirectoryTooLarge()
    val canonical = path.trim('/')
    if (canonical.isEmpty()) return
    if (canonical.split('/').any { segment ->
            val invalidCharacter = segment.any { it == '\\' || it.isISOControl() }
            segment.isEmpty() || segment in setOf(".", "..") || invalidCharacter
        }
    ) {
        invalidBoundaryDirectory()
    }
}

internal object BoundaryDirectoryCodec {
    fun encode(entry: BoundaryEntry): ByteArray {
        val bytes = BoundaryDirectoryBuffer()
        return try {
            DataOutputStream(bytes).use { output ->
                output.writeInt(1)
                output.writeBoundaryField(entry.id, bytes)
                output.writeBoundaryField(entry.path, bytes)
                output.writeBoundaryField(entry.name, bytes)
                output.writeBoolean(entry.directory)
                output.writeLong(entry.size)
                output.writeNullableBoundaryField(entry.version, bytes)
                output.writeNullableBoundaryField(entry.mimeType, bytes)
            }
            if (bytes.size() > BOUNDARY_DIRECTORY_BYTES) boundaryDirectoryTooLarge()
            bytes.toByteArray()
        } finally {
            bytes.wipe()
        }
    }

    fun decode(bytes: ByteArray): BoundaryEntry =
        try {
            DataInputStream(ByteArrayInputStream(bytes)).use { input ->
                if (input.readInt() != 1) invalidBoundaryDirectory()
                val id = input.readBoundaryField()
                val path = input.readBoundaryField()
                val name = input.readBoundaryField()
                val directory = input.readBoundaryBoolean()
                val size = input.readLong()
                val version = input.readNullableBoundaryField()
                val mime = input.readNullableBoundaryField()
                if (input.read() != -1) invalidBoundaryDirectory()
                BoundaryEntry(id, path, name, directory, size, version, mime)
            }
        } catch (_: EOFException) {
            invalidBoundaryDirectory()
        }
}

private fun DataOutputStream.writeNullableBoundaryField(
    value: String?,
    buffer: BoundaryDirectoryBuffer,
) {
    writeBoolean(value != null)
    if (value != null) writeBoundaryField(value, buffer)
}

private fun DataOutputStream.writeBoundaryField(
    value: String,
    buffer: BoundaryDirectoryBuffer,
) {
    if (value.length > BOUNDARY_DIRECTORY_BYTES) boundaryDirectoryTooLarge()
    requireValidBoundaryUnicode(value)
    val encoded = value.toByteArray(Charsets.UTF_8)
    try {
        if (buffer.size().toLong() + 4 + encoded.size > BOUNDARY_DIRECTORY_BYTES) boundaryDirectoryTooLarge()
        writeInt(encoded.size)
        write(encoded)
    } finally {
        encoded.fill(0)
    }
}

private fun DataInputStream.readBoundaryBoolean(): Boolean =
    when (readUnsignedByte()) {
        0 -> false
        1 -> true
        else -> invalidBoundaryDirectory()
    }

private fun DataInputStream.readNullableBoundaryField(): String? =
    if (readBoundaryBoolean()) readBoundaryField() else null

private fun DataInputStream.readBoundaryField(): String {
    val length = readInt()
    if (length !in 0..BOUNDARY_DIRECTORY_BYTES || length > available()) invalidBoundaryDirectory()
    val bytes = ByteArray(length)
    return try {
        readFully(bytes)
        Charsets.UTF_8
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(bytes))
            .toString()
    } catch (_: CharacterCodingException) {
        invalidBoundaryDirectory()
    } finally {
        bytes.fill(0)
    }
}

private fun requireValidBoundaryUnicode(value: String) {
    var index = 0
    while (index < value.length) {
        val next = value[index]
        if (next.isHighSurrogate()) {
            if (index + 1 >= value.length || !value[index + 1].isLowSurrogate()) invalidBoundaryDirectory()
            index++
        } else if (next.isLowSurrogate()) {
            invalidBoundaryDirectory()
        }
        index++
    }
}

private fun boundaryDirectoryTooLarge(): Nothing = throw OpenCloudException(OpenCloudError.DirectoryListingTooLarge)

private class BoundaryDirectoryBuffer : ByteArrayOutputStream() {
    fun wipe() {
        buf.fill(0)
        reset()
    }
}
