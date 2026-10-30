package eu.opencloud.android.next.core.sync

import java.io.File
import java.io.FileInputStream
import java.io.OutputStream

/** Authenticates original rclone blocks through a discard sink without retaining plaintext. */
internal fun authenticateOfflineCiphertext(
    file: File,
    material: ByteArray,
    cipherFromMaterial: (ByteArray) -> VaultCipherEngine,
    checkActive: () -> Unit,
) {
    cipherFromMaterial(material).use { cipher ->
        val sink =
            object : OutputStream() {
                override fun write(value: Int) {
                    checkActive()
                }

                override fun write(
                    buffer: ByteArray,
                    offset: Int,
                    length: Int,
                ) {
                    checkActive()
                }
            }
        FileInputStream(file).use { input ->
            val guarded =
                object : java.io.FilterInputStream(input) {
                    override fun read(): Int {
                        checkActive()
                        return `in`.read()
                    }

                    override fun read(
                        buffer: ByteArray,
                        offset: Int,
                        length: Int,
                    ): Int {
                        checkActive()
                        return `in`.read(buffer, offset, length)
                    }
                }
            cipher.decryptContent(guarded, sink, Long.MAX_VALUE)
        }
    }
}
