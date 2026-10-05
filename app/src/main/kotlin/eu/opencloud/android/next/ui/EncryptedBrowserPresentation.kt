package eu.opencloud.android.next.ui

import eu.opencloud.android.next.core.datastore.FileDisplayOptions
import eu.opencloud.android.next.core.datastore.SettingsBrowserLayout

internal data class EncryptedBrowserPresentation(
    val layout: SettingsBrowserLayout,
    val display: FileDisplayOptions,
    val revision: Long,
    val loadThumbnail: suspend (String) -> ByteArray?,
)
