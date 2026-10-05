package eu.opencloud.android.next.core.security

import android.content.Context
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.model.auth.AuthTokens
import eu.opencloud.android.next.core.model.auth.OidcClientRegistration
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** Process-wide account ownership. Network refresh is serialized only within the same account. */
class AccountSessions(
    private val credentials: CredentialStore,
    private val clock: AppClock = SystemAppClock,
) {
    private val accounts = ConcurrentHashMap<String, Any>()
    private val generations = ConcurrentHashMap<String, AtomicLong>()

    /** A cheap process-local lease revoked before account credentials are removed or replaced. */
    fun beginLease(accountId: String): () -> Boolean =
        synchronized(lock(accountId)) {
            val generation = generation(accountId).get()
            val present = credentials.readTokens(accountId) != null || credentials.readBasicPassword(accountId) != null
            ({ present && generation(accountId).get() == generation })
        }

    fun tokens(
        accountId: String,
        refresh: (AuthTokens) -> AuthTokens,
    ): AuthTokens =
        synchronized(lock(accountId)) {
            val current = credentials.readTokens(accountId) ?: reauthenticate()
            val now = clock.epochMillis() / 1000
            // No refresh token is a supported short-lived session, usable until actual expiry.
            if (current.expiresAtEpochSeconds > now &&
                (current.refreshToken.isNullOrBlank() || current.expiresAtEpochSeconds - now > REFRESH_SKEW_SECONDS)
            ) {
                return@synchronized current
            }
            if (current.refreshToken.isNullOrBlank()) reauthenticate()
            val refreshed =
                try {
                    refresh(current)
                } catch (exception: OpenCloudException) {
                    if (exception.error == OpenCloudError.ClientRegistrationRequired) {
                        generation(accountId).incrementAndGet()
                        credentials
                            .readClientRegistration(
                                "account:$accountId",
                            )?.let(credentials::invalidateClientRegistration)
                        credentials.remove(accountId)
                    }
                    if (exception.error == OpenCloudError.AuthenticationRequired) {
                        generation(accountId).incrementAndGet()
                        credentials.remove(accountId)
                    }
                    throw exception
                }
            if (refreshed.expiresAtEpochSeconds <= now) reauthenticate()
            val committed = refreshed.copy(refreshToken = refreshed.refreshToken ?: current.refreshToken)
            credentials.saveTokens(accountId, committed)
            committed
        }

    fun save(
        accountId: String,
        tokens: AuthTokens,
        registration: OidcClientRegistration? = null,
    ): Unit =
        synchronized(lock(accountId)) {
            generation(accountId).incrementAndGet()
            if (registration == null) {
                credentials.saveTokens(accountId, tokens)
            } else {
                credentials.saveRegisteredTokens(accountId, tokens, registration)
            }
            Unit
        }

    /** Returns only after any in-flight refresh has finished, then removes its committed result. */
    fun remove(accountId: String) =
        synchronized(lock(accountId)) {
            generation(accountId).incrementAndGet()
            credentials.remove(accountId)
        }

    private fun lock(accountId: String): Any = accounts.computeIfAbsent(accountId) { Any() }

    private fun generation(accountId: String): AtomicLong = generations.computeIfAbsent(accountId) { AtomicLong() }

    private fun reauthenticate(): Nothing = throw OpenCloudException(OpenCloudError.AuthenticationRequired)

    companion object {
        private const val REFRESH_SKEW_SECONDS = 60L

        @Volatile private var instance: AccountSessions? = null

        fun get(context: Context): AccountSessions =
            instance ?: synchronized(this) {
                instance ?: AccountSessions(KeystoreCredentialStore(context.applicationContext)).also { instance = it }
            }
    }
}
