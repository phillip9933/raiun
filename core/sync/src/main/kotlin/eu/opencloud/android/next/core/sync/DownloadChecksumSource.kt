package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.network.DownloadExpectation

internal data class DownloadChecksumSource(
    val url: String,
    val authorization: String,
    val expectation: DownloadExpectation,
)
