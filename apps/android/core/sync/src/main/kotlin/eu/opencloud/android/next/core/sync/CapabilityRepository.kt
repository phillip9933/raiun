package eu.opencloud.android.next.core.sync

import android.content.Context
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.model.AppClock
import eu.opencloud.android.next.core.model.SystemAppClock
import eu.opencloud.android.next.core.model.auth.ServerCapabilities
import eu.opencloud.android.next.core.network.OpenCloudApi
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.toOpenCloudError
import eu.opencloud.android.next.core.security.TlsPolicy
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.OkHttpClient
import java.util.concurrent.ConcurrentHashMap

/** Freshness is process-local: after restart mutations must obtain policy again. */
class CapabilityRepository(
    private val clock: AppClock = SystemAppClock,
    private val fetch: suspend (AccountEntity, String) -> ServerCapabilities,
) {
    private val entries = ConcurrentHashMap<String, Entry>()

    @Suppress("TooGenericExceptionCaught", "ThrowsCount") // One safe boundary for injected transport/parser failures.
    suspend fun refresh(
        account: AccountEntity,
        authorization: String,
        publish: suspend (ServerCapabilities) -> Boolean,
    ): ServerCapabilities {
        val entry = entries.getOrPut(account.id + "\n" + account.serverUrl) { Entry() }
        return entry.mutex.withLock {
            val now = clock.epochMillis()
            val age = now - entry.checkedAt
            val lifetime = if (entry.failure == null) SUCCESS_TTL else FAILURE_TTL
            if (entry.checkedAt != Long.MIN_VALUE &&
                age in 0 until lifetime &&
                entry.cachedRevision == entry.revision.get()
            ) {
                entry.failure?.let { throw OpenCloudException(it) }
                return@withLock requireNotNull(entry.capabilities)
            }
            val revision = entry.revision.get()
            try {
                val capabilities = fetch(account, authorization)
                if (!publish(capabilities)) throw OpenCloudException(OpenCloudError.AuthenticationRequired)
                entry.capabilities = capabilities
                entry.failure = null
                entry.checkedAt = clock.epochMillis()
                entry.cachedRevision = revision
                capabilities
            } catch (failure: Exception) {
                // Mapping rethrows cancellation; cancelled refreshes never poison the cache.
                entry.failure = failure.toOpenCloudError()
                entry.checkedAt = clock.epochMillis()
                entry.cachedRevision = revision
                throw OpenCloudException(requireNotNull(entry.failure))
            }
        }
    }

    fun invalidate(accountId: String) {
        entries.filterKeys { it.startsWith("$accountId\n") }.values.forEach { it.revision.incrementAndGet() }
    }

    private class Entry {
        val mutex = Mutex()
        val revision =
            java.util.concurrent.atomic
                .AtomicInteger()
        var cachedRevision = -1
        var checkedAt = Long.MIN_VALUE
        var capabilities: ServerCapabilities? = null
        var failure: OpenCloudError? = null
    }

    companion object {
        private const val SUCCESS_TTL = 5 * 60_000L
        private const val FAILURE_TTL = 30_000L

        @Volatile
        private var instance: CapabilityRepository? = null

        fun get(context: Context): CapabilityRepository =
            instance ?: synchronized(this) {
                instance ?: CapabilityRepository { account, authorization ->
                    val client = TlsPolicy(context.applicationContext).applyTo(OkHttpClient(), account.serverUrl)
                    OpenCloudApi(client).capabilities(account.serverUrl, authorization)
                }.also { instance = it }
            }
    }
}

internal suspend fun CapabilityRepository.refresh(
    account: AccountEntity,
    authorization: String,
    store: FileBrowserStore,
) = refresh(account, authorization) { store.publishCapabilities(account.id, account.serverUrl, it) }
