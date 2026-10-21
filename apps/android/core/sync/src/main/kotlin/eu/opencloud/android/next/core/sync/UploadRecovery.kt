package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.TransferConflictException
import eu.opencloud.android.next.core.network.TransferHttpException

internal suspend fun uploadAndVerify(
    transfer: TransferEntity,
    upload: suspend () -> Unit,
    verify: () -> Unit,
    uploaded: suspend () -> Unit = {},
    recreateMissing: suspend () -> Unit = upload,
) {
    // Progress can reach the end before the response arrives. Verify first; only confirmed absence permits recreation.
    val completeCheckpoint =
        transfer.verificationPending ||
            (transfer.bytesTotal > 0 && transfer.bytesTransferred == transfer.bytesTotal && transfer.attemptCount > 1)
    if (completeCheckpoint) {
        if (!verifyRecovery(transfer, verify)) writeAndVerify(transfer, recreateMissing, verify, uploaded)
    } else {
        val emptyRecovery = transfer.bytesTotal == 0L && transfer.attemptCount > 1
        if (!emptyRecovery || !verifyRecovery(transfer, verify)) writeAndVerify(transfer, upload, verify, uploaded)
    }
}

private suspend fun writeAndVerify(
    transfer: TransferEntity,
    upload: suspend () -> Unit,
    verify: () -> Unit,
    uploaded: suspend () -> Unit,
) {
    try {
        upload()
    } catch (_: TransferConflictException) {
        // A first attempt must surface a pre-existing target as a conflict. A later
        // attempt may reconcile an earlier ambiguous write, but only after byte verification.
        if (transfer.attemptCount <= 1) throw TransferConflictException()
        verifyExistingTarget(verify)
        return
    }
    uploaded()
    verify()
}

private fun verifyExistingTarget(verify: () -> Unit) {
    try {
        verify()
    } catch (failure: OpenCloudException) {
        if (failure.error == OpenCloudError.PreconditionFailed) throw TransferConflictException()
        throw failure
    }
}

private fun verifyRecovery(
    transfer: TransferEntity,
    verify: () -> Unit,
): Boolean =
    try {
        verify()
        true
    } catch (failure: TransferHttpException) {
        // Never recreate an edited/deleted file or replay an unconditional replacement.
        if (failure.statusCode != 404 || transfer.overwrite || transfer.expectedETag != null) throw failure
        false
    }
