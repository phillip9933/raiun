package eu.opencloud.android.next.core.network

import java.io.IOException

/** A refused/unsent transport request. Contains no URLs, aliases, tokens or platform error text. */
open class TransportPolicyException(
    val error: OpenCloudError,
) : IOException(error.safeMessage())
