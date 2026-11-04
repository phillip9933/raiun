package eu.opencloud.android.next.feature.files

/** Creation-time guidance only; existing encrypted locations keep their original unlock rules. */
internal object EncryptedCreationPasswordPolicy {
    const val MINIMUM_CHARACTERS = 12

    fun isAcceptable(password: String): Boolean = password.codePointCount(0, password.length) >= MINIMUM_CHARACTERS
}
