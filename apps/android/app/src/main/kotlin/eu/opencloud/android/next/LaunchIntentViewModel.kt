package eu.opencloud.android.next

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.sync.FolderShortcutTarget
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import java.security.MessageDigest
import java.security.SecureRandom

/** Payloads stay in memory; saved state contains only a salted consumed-event replay marker. */
internal class LaunchIntentViewModel : ViewModel() {
    var pending by mutableStateOf<LaunchRequest?>(null)
        private set
    var folderNavigation by mutableStateOf<LaunchFolderNavigation?>(null)
        private set
    private var initialized = false
    private var nextId = 0L
    private var replaySalt = ByteArray(MARKER_BYTES).also(SecureRandom()::nextBytes)
    private var consumedDigest: ByteArray? = null

    fun acceptInitial(
        intent: Intent?,
        savedState: Bundle? = null,
    ) {
        if (initialized) return
        initialized = true
        val savedSalt = savedState?.getByteArray(SALT_KEY)
        val savedDigest = savedState?.getByteArray(DIGEST_KEY)
        if (savedSalt?.size == MARKER_BYTES && savedDigest?.size == MARKER_BYTES) {
            replaySalt = savedSalt.copyOf()
            consumedDigest = savedDigest.copyOf()
            val uri = intent?.dataString
            if (uri != null && MessageDigest.isEqual(savedDigest, digest(uri))) return
        }
        acceptNew(intent)
    }

    /** Empty launcher intents and stale history entries cannot replace an unprocessed request. */
    fun acceptNew(intent: Intent?): Boolean {
        val uri =
            intent?.takeUnless { it.flags and Intent.FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY != 0 }?.dataString
                ?: return false
        // A genuine new delivery is a new event even when its URI matches a consumed event.
        consumedDigest = null
        folderNavigation = null
        pending = LaunchRequest(++nextId, uri, intent.data?.scheme == FolderShortcutTarget.SCHEME)
        return true
    }

    fun isPending(id: Long?): Boolean = id != null && pending?.id == id

    fun openFolder(
        id: Long,
        resource: ResourceEntity,
    ) {
        if (isPending(id)) folderNavigation = LaunchFolderNavigation(id, resource = resource)
    }

    fun openSharedFolder(
        id: Long,
        request: SharedFolderRequest,
    ) {
        if (isPending(id)) folderNavigation = LaunchFolderNavigation(id, shared = request)
    }

    /** A late completion must not consume a newer intent, including one with the same URI. */
    fun consume(id: Long): Boolean {
        if (!isPending(id)) return false
        consumedDigest = digest(requireNotNull(pending).uri)
        pending = null
        folderNavigation = null
        return true
    }

    fun saveReplayMarker(outState: Bundle) {
        val digest = consumedDigest
        if (digest != null) {
            outState.putByteArray(SALT_KEY, replaySalt.copyOf())
            outState.putByteArray(DIGEST_KEY, digest.copyOf())
        } else {
            outState.remove(SALT_KEY)
            outState.remove(DIGEST_KEY)
        }
    }

    private fun digest(uri: String): ByteArray =
        MessageDigest.getInstance("SHA-256").run {
            update("raiun.launch-replay.v1\u0000".toByteArray(Charsets.UTF_8))
            update(replaySalt)
            digest(uri.toByteArray(Charsets.UTF_8))
        }

    private companion object {
        const val MARKER_BYTES = 32
        const val SALT_KEY = "launch-consumed-salt-v1"
        const val DIGEST_KEY = "launch-consumed-digest-v1"
    }
}

// Deliberately not a data class: diagnostic stringification must not include the callback URL.
internal class LaunchRequest(
    val id: Long,
    val uri: String,
    val folderShortcut: Boolean,
)

/** Keep a validated but not-yet-applied navigation across lock/configuration changes. */
internal class LaunchFolderNavigation(
    val id: Long,
    val resource: ResourceEntity? = null,
    val shared: SharedFolderRequest? = null,
)

internal fun Activity.consumeLaunchRequest(
    owner: LaunchIntentViewModel,
    id: Long,
): Boolean {
    if (!owner.consume(id)) return false
    // Consumption and intent clearing are synchronous on Main, after the matching-ID check.
    intent = Intent(intent).setData(null)
    return true
}
