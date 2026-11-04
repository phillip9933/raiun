package eu.opencloud.android.next.core.model

/** Existing Room TEXT values. UNKNOWN is a read-only sentinel, never a new persisted state. */
enum class TransferState {
    QUEUED,
    RUNNING,
    RETRY,
    CONFLICT,
    AWAITING_UNLOCK,
    SUCCEEDED,
    FAILED,
    CANCELLED,
    UNKNOWN,
    ;

    val persistedValue: String
        get() {
            check(this != UNKNOWN) { "Unknown transfer state cannot be persisted." }
            return name
        }

    /** Durable intent that a worker may claim, including interrupted RUNNING work after process death. */
    val isRunnable: Boolean get() = this == QUEUED || this == RUNNING || this == RETRY

    /** Ciphertext awaiting authentication remains active but must not run or publish plaintext. */
    val isActive: Boolean get() = isRunnable || this == AWAITING_UNLOCK

    val isHistory: Boolean get() = this == SUCCEEDED || this == CANCELLED

    val requiresAttention: Boolean get() = this == FAILED || this == CONFLICT || this == UNKNOWN

    /** Conflict retry requires the caller's separate explicit resolution and destination guards. */
    val allowsExplicitRetry: Boolean get() = this == FAILED || this == CANCELLED || this == CONFLICT || this == RETRY

    val allowsRetryWithoutConflictDecision: Boolean get() = allowsExplicitRetry && this != CONFLICT

    val allowsBulkRetry: Boolean get() = this == FAILED || this == RETRY

    companion object {
        /** Exact matching preserves historical values; corrupt/future values never become runnable or successful. */
        fun fromPersisted(value: String?): TransferState =
            entries.firstOrNull { it != UNKNOWN && it.name == value } ?: UNKNOWN
    }
}
