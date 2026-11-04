package eu.opencloud.android.next.core.sync

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.interfaces.SecretBox
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import java.lang.reflect.InvocationTargetException

private val hostSecretBox by lazy { LazySodiumJava(SodiumJava()) }

/** Cross-module access to Crypto's existing test seam; production and native Android providers stay unchanged. */
private val restoreHostCipher by lazy {
    RcloneVaultCipher.Companion.javaClass.methods.single { method ->
        method.name.startsWith("fromKeyMaterialWithSecretBox\$") &&
            method.returnType == RcloneVaultCipher::class.java &&
            method.parameterTypes.contentEquals(arrayOf(ByteArray::class.java, SecretBox.Native::class.java))
    }
}

internal fun jvmRcloneVaultCipher(material: ByteArray): RcloneVaultCipher =
    try {
        restoreHostCipher.invoke(RcloneVaultCipher.Companion, material, hostSecretBox) as RcloneVaultCipher
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
