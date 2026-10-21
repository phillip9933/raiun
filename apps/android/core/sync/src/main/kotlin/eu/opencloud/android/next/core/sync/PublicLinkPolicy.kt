package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import java.time.LocalDate
import java.time.ZoneOffset

internal fun validatePublicLinkPolicy(
    account: AccountEntity,
    password: String?,
    expiration: LocalDate?,
    updating: Boolean = false,
    today: LocalDate = LocalDate.now(ZoneOffset.UTC),
) {
    // An omitted update password preserves the server's existing secret. Never infer that it is absent.
    if (account.publicLinkPasswordEnforced && (!updating || password != null)) {
        require(!password.isNullOrBlank()) { "This server requires a public link password." }
    }
    if (account.publicLinkExpirationEnforced) {
        requireNotNull(expiration) { "This server requires a public link expiration date." }
    }
    if (expiration != null) {
        require(expiration.isAfter(today)) { "Choose a future expiration date." }
        val days = account.publicLinkExpirationDays
        if (account.publicLinkExpirationEnforced && days != null && days > 0) {
            require(!expiration.isAfter(today.plusDays(days.toLong()))) {
                "The expiration exceeds the server's allowed lifetime."
            }
        }
    }
}
