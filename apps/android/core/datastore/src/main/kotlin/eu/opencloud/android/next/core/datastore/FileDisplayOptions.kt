package eu.opencloud.android.next.core.datastore

/** Inverted proto flags preserve visible metadata for existing installations. */
data class FileDisplayOptions(
    val showSize: Boolean = true,
    val showModified: Boolean = true,
    val showExtensions: Boolean = true,
    val showHidden: Boolean = false,
)
