package eu.opencloud.android.next.ui

import kotlinx.coroutines.CancellationException

internal enum class VaultUnlockStage {
    LOCAL_RESTORE,
    SERVER_VERIFICATION,
    INITIAL_DIRECTORY,
    FINAL_ADMISSION,
    TOTAL,
}

internal enum class VaultUnlockOutcome {
    SUCCESS,
    REJECTED,
    CANCELLED,
    FAILURE,
}

/** Optional measurement only; no identity, key, path, logging or persistence enters this seam. */
internal class VaultUnlockTiming(
    private val clock: () -> Long = System::nanoTime,
    private val record: (VaultUnlockStage, VaultUnlockOutcome, Long) -> Unit,
) {
    fun begin(stage: VaultUnlockStage): VaultUnlockSpan =
        VaultUnlockSpan(stage, runCatching(clock).getOrNull(), clock, record)
}

internal class VaultUnlockSpan(
    private val stage: VaultUnlockStage,
    private val started: Long?,
    private val clock: () -> Long,
    private val record: (VaultUnlockStage, VaultUnlockOutcome, Long) -> Unit,
) {
    private var finished = false

    fun finish(outcome: VaultUnlockOutcome) {
        if (finished) return
        finished = true
        // Instrumentation must not affect admission, cleanup or the original failure/cancellation.
        runCatching {
            if (started != null) record(stage, outcome, (clock() - started).coerceAtLeast(0))
        }
    }
}

@Suppress("TooGenericExceptionCaught") // Classify and rethrow the original failure without changing its outcome.
internal suspend inline fun <T> VaultUnlockTiming?.measure(
    stage: VaultUnlockStage,
    operation: () -> T,
): T {
    if (this == null) return operation()
    val span = begin(stage)
    try {
        return operation().also { span.finish(VaultUnlockOutcome.SUCCESS) }
    } catch (cancelled: CancellationException) {
        span.finish(VaultUnlockOutcome.CANCELLED)
        throw cancelled
    } catch (failure: Throwable) {
        span.finish(VaultUnlockOutcome.FAILURE)
        throw failure
    }
}
