package eu.opencloud.android.next.core.crypto

/** Invalid ciphertext is distinct from an Android provider refusing permission to read a source. */
class VaultContentIntegrityException : SecurityException("Encrypted file integrity check failed")
