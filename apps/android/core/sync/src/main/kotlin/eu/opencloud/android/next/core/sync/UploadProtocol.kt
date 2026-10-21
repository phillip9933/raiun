package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.TransferEntity

private const val TUS_THRESHOLD = 10L * 1024 * 1024

// OpenCloud's collection TUS endpoint does not propagate destination preconditions.
// Use it only when the user explicitly authorized an unconditional replacement.
internal fun TransferEntity.canUseTusUpload(serverSupportsTus: Boolean): Boolean =
    serverSupportsTus && allowsUnconditionalReplacement() && bytesTotal >= TUS_THRESHOLD

internal fun TransferEntity.withoutUnprotectedTusSession(): TransferEntity =
    if (allowsUnconditionalReplacement()) this else copy(tusUrl = null, tusOffset = 0)

internal fun TransferEntity.allowsUnconditionalReplacement(): Boolean = overwrite && expectedETag == null

internal fun TransferEntity.requiresUploadVerificationOnRetry(): Boolean =
    verificationPending ||
        (direction == "UPLOAD" && attemptCount > 0 && bytesTotal > 0 && bytesTransferred >= bytesTotal)
