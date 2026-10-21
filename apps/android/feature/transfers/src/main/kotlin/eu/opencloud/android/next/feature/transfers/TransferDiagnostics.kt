package eu.opencloud.android.next.feature.transfers

/** Only application-defined codes may be presented, even if old database rows contain arbitrary text. */
internal fun safeTransferDiagnosticCode(code: String?): String? =
    code?.takeIf {
        it in TRANSFER_DIAGNOSTIC_CODES || Regex("(?:HTTP|SERVER)_[1-5][0-9]{2}").matches(it)
    }

private val TRANSFER_DIAGNOSTIC_CODES =
    setOf(
        "CONNECTIVITY",
        "TIMEOUT",
        "AUTHENTICATION_REQUIRED",
        "CLIENT_REGISTRATION_REQUIRED",
        "ACCESS_DENIED",
        "PASSWORD_REQUIRED",
        "NOT_FOUND",
        "CONFLICT",
        "PRECONDITION",
        "PRECONDITION_FAILED",
        "DOWNLOAD_INTEGRITY",
        "INVALID_RESPONSE",
        "DIRECTORY_LISTING_TOO_LARGE",
        "REMOTE_QUOTA",
        "LOCAL_STORAGE",
        "LOCAL_STORAGE_WRITE_FAILED",
        "SOURCE_UNAVAILABLE",
        "SOURCE_CHANGED",
        "SOURCE_PERMISSION",
        "UNSUPPORTED",
        "TRUST",
        "UNKNOWN",
        "REMOTE_NOT_READY",
        "RATE_LIMITED",
        "SHARE_PASSWORD_POLICY",
        "SHARE_PERMISSIONS",
        "SHARE_RESOURCE_REFERENCE",
        "SHARE_SPACE_ROOT",
        "SHARE_EXPIRATION",
        "SHARE_REQUEST_FORMAT",
        "SHARE_UNKNOWN",
    )
