package eu.opencloud.android.next.core.crypto

import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.params.KeyParameter

/**
 * EME wide-block transform adapted from rfjakob/eme v1.2.0 (MIT).
 * Copyright (c) 2015 Jakob Unterwurzacher; full license is bundled in
 * assets/third-party/vault-crypto/EME-MIT-LICENSE.
 */
internal object Eme {
    fun transform(
        key: ByteArray,
        tweak: ByteArray,
        input: ByteArray,
        encrypt: Boolean,
    ): ByteArray {
        require(tweak.size == 16 && input.isNotEmpty() && input.size % 16 == 0 && input.size <= 2048)
        val aes = AESEngine.newInstance()
        aes.init(encrypt, KeyParameter(key))
        val m = input.size / 16
        val zero = ByteArray(16)
        val li = ByteArray(16)
        // L_i is always AES-encryption, even when the EME direction is decryption.
        val aesEncrypt = AESEngine.newInstance()
        aesEncrypt.init(true, KeyParameter(key))
        aesEncrypt.processBlock(zero, 0, li, 0)
        val lTable =
            Array(m) {
                double(li)
                li.copyOf()
            }
        val result = ByteArray(input.size)
        val block = ByteArray(16)
        for (j in 0 until m) {
            xor(block, input, j * 16, lTable[j])
            aes.processBlock(block, 0, result, j * 16)
        }
        val mp = tweak.copyOf()
        for (j in 0 until m) xorInPlace(mp, result, j * 16)
        val mc = ByteArray(16)
        aes.processBlock(mp, 0, mc, 0)
        val mix = mp.copyOf()
        xorInPlace(mix, mc, 0)
        for (j in 1 until m) {
            double(mix)
            for (i in 0 until 16) result[j * 16 + i] = (result[j * 16 + i].toInt() xor mix[i].toInt()).toByte()
        }
        val first = mc.copyOf()
        xorInPlace(first, tweak, 0)
        for (j in 1 until m) xorInPlace(first, result, j * 16)
        first.copyInto(result, 0)
        for (j in 0 until m) {
            aes.processBlock(result, j * 16, block, 0)
            xor(result, block, 0, lTable[j], j * 16)
        }
        zero.fill(0)
        li.fill(0)
        block.fill(0)
        mp.fill(0)
        mc.fill(0)
        mix.fill(0)
        first.fill(0)
        lTable.forEach { it.fill(0) }
        return result
    }

    private fun double(bytes: ByteArray) {
        val carry = (bytes[15].toInt() ushr 7) and 1
        for (i in 15 downTo 1) {
            bytes[i] = (((bytes[i].toInt() and 0xff) shl 1) or ((bytes[i - 1].toInt() ushr 7) and 1)).toByte()
        }
        bytes[0] = (((bytes[0].toInt() and 0xff) shl 1) xor (0x87 * carry)).toByte()
    }

    private fun xorInPlace(
        out: ByteArray,
        other: ByteArray,
        offset: Int,
    ) {
        for (i in 0 until 16) out[i] = (out[i].toInt() xor other[offset + i].toInt()).toByte()
    }

    private fun xor(
        out: ByteArray,
        input: ByteArray,
        offset: Int,
        mask: ByteArray,
        outOffset: Int = 0,
    ) {
        for (i in 0 until 16) out[outOffset + i] = (input[offset + i].toInt() xor mask[i].toInt()).toByte()
    }
}
