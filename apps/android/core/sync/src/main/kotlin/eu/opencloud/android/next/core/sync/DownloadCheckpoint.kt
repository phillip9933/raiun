package eu.opencloud.android.next.core.sync

import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.Base64

internal fun prepareDownloadCheckpoint(
    partial: File,
    validator: File,
    identity: String,
    length: Long,
    canResume: Boolean,
): Long {
    val key = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(identity.toByteArray()))
    val matching = canResume && validator.length() == key.length.toLong() && validator.readText() == key
    val offset = partial.takeIf { matching && it.length() in 1 until length }?.length() ?: 0
    if (offset == 0L) FileOutputStream(partial).use { it.fd.sync() }
    // A torn metadata write cannot match the complete identity, so the next attempt restarts safely.
    FileOutputStream(validator).use {
        it.write(key.toByteArray())
        it.fd.sync()
    }
    return offset
}
