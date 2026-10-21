package eu.opencloud.android.next.core.sync

import android.content.Context
import android.content.SharedPreferences
import java.security.MessageDigest

/** Stores acknowledged creates until a complete server snapshot exposes their drive IDs. */
interface PendingSpaceCreationStore {
    fun get(key: PendingSpaceCreationKey): String?

    fun put(
        key: PendingSpaceCreationKey,
        driveId: String,
    )

    fun remove(key: PendingSpaceCreationKey)
}

/** Identity deliberately excludes authorization data. */
data class PendingSpaceCreationKey(
    val accountId: String,
    val serverUrl: String,
    val normalizedName: String,
) {
    companion object {
        fun create(
            accountId: String,
            serverUrl: String,
            name: String,
        ) = PendingSpaceCreationKey(
            accountId = accountId,
            serverUrl = serverUrl.trim().trimEnd('/'),
            normalizedName = name.trim(),
        )
    }
}

/** Process-local default suitable for tests; production can inject a durable implementation. */
class InMemoryPendingSpaceCreationStore : PendingSpaceCreationStore {
    private val entries = mutableMapOf<PendingSpaceCreationKey, String>()

    @Synchronized
    override fun get(key: PendingSpaceCreationKey): String? = entries[key]

    @Synchronized
    override fun put(
        key: PendingSpaceCreationKey,
        driveId: String,
    ) {
        entries[key] = driveId
    }

    @Synchronized
    override fun remove(key: PendingSpaceCreationKey) {
        entries.remove(key)
    }
}

/** Durable journal for accepted creates. No authorization header or credential is stored. */
class PendingSpaceCreations(
    context: Context,
) : PendingSpaceCreationStore {
    private val preferences: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    @Synchronized
    override fun get(key: PendingSpaceCreationKey): String? = preferences.getString(storageKey(key), null)

    @Synchronized
    override fun put(
        key: PendingSpaceCreationKey,
        driveId: String,
    ) {
        check(preferences.edit().putString(storageKey(key), driveId).commit()) {
            "Could not persist the acknowledged space creation."
        }
    }

    @Synchronized
    override fun remove(key: PendingSpaceCreationKey) {
        check(preferences.edit().remove(storageKey(key)).commit()) {
            "Could not clear the acknowledged space creation."
        }
    }

    private fun storageKey(key: PendingSpaceCreationKey): String {
        val source = "${key.accountId}\u0000${key.serverUrl}\u0000${key.normalizedName}"
        val digest = MessageDigest.getInstance("SHA-256").digest(source.toByteArray(Charsets.UTF_8))
        return PREFIX + digest.joinToString("") { byte -> "%02x".format(byte) }
    }

    private companion object {
        const val PREFERENCES_NAME = "pending_space_creations"
        const val PREFIX = "creation_"
    }
}

sealed interface SpaceCreationResult {
    data class Created(
        val space: eu.opencloud.android.next.core.database.SpaceEntity,
    ) : SpaceCreationResult

    data class AwaitingDiscovery(
        val driveId: String,
        val retrySafe: Boolean = true,
    ) : SpaceCreationResult
}
