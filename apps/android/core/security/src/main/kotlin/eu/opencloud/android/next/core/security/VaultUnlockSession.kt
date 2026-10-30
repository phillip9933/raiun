package eu.opencloud.android.next.core.security

import android.app.KeyguardManager
import android.content.Context
import android.os.PowerManager

/** Device remember choices and revocation epochs are stored by [VaultDeviceRememberStore]. */
class VaultUnlockPolicy internal constructor(
    context: Context,
    private val commitDevicePolicy: (Boolean, () -> Unit) -> Unit,
) {
    constructor(context: Context) : this(
        context,
        { value, commit -> VaultDeviceRememberStore(context.applicationContext).changeAskEveryTime(value, commit) },
    )

    private val context = context.applicationContext
    private val preferences get() = context.getSharedPreferences("vault-unlock-policy", Context.MODE_PRIVATE)

    fun askEveryTime(): Boolean = runCatching { preferences.getBoolean("ask-every-time", false) }.getOrDefault(true)

    fun setAskEveryTime(value: Boolean) {
        processVaultUnlocks.invalidate {}
        try {
            commitDevicePolicy(value) {
                check(preferences.edit().putBoolean("ask-every-time", value).commit())
            }
        } finally {
            processVaultUnlocks.invalidate {}
        }
    }
}

/** Process-memory convenience following a proven password/biometric unlock of this exact location. */
class VaultUnlockSession internal constructor(
    private val cache: VerifiedVaultKeyCache,
    private val available: () -> Boolean,
) {
    constructor(context: Context) : this(processVaultUnlocks, deviceSessionAvailable(context.applicationContext))

    /** Capture before authentication begins, so a late completion cannot resurrect a revoked grant. */
    fun beginUnlock(): VaultUnlockGrant? = cache.begin(available)

    fun remember(
        grant: VaultUnlockGrant?,
        identity: VaultIdentity,
        accountSnapshot: Any,
        verifiedKeyMaterial: ByteArray,
        credentialPermit: () -> Boolean,
    ): VaultUnlockRememberResult =
        cache.remember(grant, identity, accountSnapshot, verifiedKeyMaterial, credentialPermit, available)

    /** The caller wipes the returned copy and must prove a fresh repository session before use. */
    fun reuse(
        identity: VaultIdentity,
        accountSnapshot: Any,
    ): VaultUnlockKey? = cache.reuse(identity, accountSnapshot, available)

    fun forget(identity: VaultIdentity) = cache.forget(identity)

    fun forgetAccount(accountId: String) = cache.forgetAccount(accountId)

    fun clear() = cache.invalidate {}

    companion object {
        internal fun clearProcess() = processVaultUnlocks.invalidate {}

        internal fun forgetProcess(identity: VaultIdentity) = processVaultUnlocks.forget(identity)

        internal fun forgetProcessAccount(accountId: String) = processVaultUnlocks.forgetAccount(accountId)
    }
}

/** Safe reason that a proven key was not admitted to the process-only phone-session cache. */
enum class VaultUnlockRememberResult {
    REMEMBERED,
    UNAVAILABLE,
    CREDENTIAL_REVOKED,
    INVALID_MATERIAL,
    MISSING_GRANT,
    STALE_GRANT,
}

/** Opaque process-only generation; contains no key, password, or durable authentication claim. */
class VaultUnlockGrant internal constructor(
    internal val owner: VerifiedVaultKeyCache,
    internal val revision: Long,
)

class VaultUnlockKey internal constructor(
    val material: ByteArray,
    private val current: () -> Boolean,
) : AutoCloseable {
    private var closed = false

    @Synchronized fun isCurrent(): Boolean = !closed && current()

    @Synchronized override fun close() {
        material.fill(0)
        closed = true
    }
}

/** All owned key copies are bounded, synchronized, and wiped on replacement, eviction or revocation. */
internal class VerifiedVaultKeyCache(
    private val capacity: Int = 8,
) {
    init {
        require(capacity in 1..8)
    }

    private data class Entry(
        val account: Any,
        val material: ByteArray,
        val credentialPermit: () -> Boolean,
    )

    private val entries = linkedMapOf<VaultIdentity, Entry>()
    private var revision = 0L

    fun begin(available: () -> Boolean): VaultUnlockGrant? {
        val atBegin = synchronized(this) { revision }
        if (!observeAvailable(available)) return null
        return synchronized(this) { if (revision == atBegin) VaultUnlockGrant(this, revision) else null }
    }

    @Suppress("LongParameterList") // The copied key must retain both account and phone-generation admission checks.
    fun remember(
        grant: VaultUnlockGrant?,
        identity: VaultIdentity,
        account: Any,
        material: ByteArray,
        credentialPermit: () -> Boolean,
        available: () -> Boolean,
    ): VaultUnlockRememberResult =
        when {
            !observeAvailable(available) -> VaultUnlockRememberResult.UNAVAILABLE
            !allowed(credentialPermit) -> VaultUnlockRememberResult.CREDENTIAL_REVOKED
            material.size != 80 -> VaultUnlockRememberResult.INVALID_MATERIAL
            else -> {
                identity.encoded.fill(0) // Validate canonical fields before accepting a cache key.
                synchronized(this) {
                    when {
                        grant == null -> VaultUnlockRememberResult.MISSING_GRANT
                        grant.owner !== this || grant.revision != revision -> VaultUnlockRememberResult.STALE_GRANT
                        else -> {
                            entries.remove(identity)?.material?.fill(0)
                            while (entries.size >= capacity) entries.remove(entries.keys.first())?.material?.fill(0)
                            entries[identity] = Entry(account, material.copyOf(), credentialPermit)
                            VaultUnlockRememberResult.REMEMBERED
                        }
                    }
                }
            }
        }

    fun reuse(
        identity: VaultIdentity,
        account: Any,
        available: () -> Boolean,
    ): VaultUnlockKey? {
        val atOpen = synchronized(this) { revision }
        if (!observeAvailable(available)) return null
        val entry = synchronized(this) { entries[identity] }
        return when {
            entry == null -> null
            entry.account != account || !allowed(entry.credentialPermit) -> {
                forgetIfSame(identity, entry)
                null
            }
            else ->
                synchronized(this) {
                    if (entries[identity] === entry && revision == atOpen) {
                        VaultUnlockKey(entry.material.copyOf()) { current(identity, entry, atOpen, available) }
                    } else {
                        null
                    }
                }
        }
    }

    private fun current(
        identity: VaultIdentity,
        entry: Entry,
        atOpen: Long,
        available: () -> Boolean,
    ): Boolean =
        when {
            !observeAvailable(available) -> false
            !allowed(entry.credentialPermit) -> {
                forgetIfSame(identity, entry)
                false
            }
            else -> synchronized(this) { revision == atOpen && entries[identity] === entry }
        }

    @Synchronized private fun forgetIfSame(
        identity: VaultIdentity,
        entry: Entry,
    ) {
        if (entries[identity] === entry) forget(identity)
    }

    @Synchronized fun forget(identity: VaultIdentity) {
        revision++
        entries.remove(identity)?.material?.fill(0)
    }

    @Synchronized fun forgetAccount(accountId: String) {
        revision++
        entries.entries.removeAll {
            if (it.key.accountId == accountId) {
                it.value.material.fill(0)
                true
            } else {
                false
            }
        }
    }

    @Synchronized fun invalidate(action: () -> Unit) {
        revision++
        entries.values.forEach { it.material.fill(0) }
        entries.clear()
        action()
    }

    private fun allowed(check: () -> Boolean): Boolean = runCatching(check).getOrDefault(false)

    private fun observeAvailable(available: () -> Boolean): Boolean = allowed(available).also { if (!it) invalidate {} }
}

private val processVaultUnlocks = VerifiedVaultKeyCache()

private fun deviceSessionAvailable(context: Context): () -> Boolean =
    {
        !VaultUnlockPolicy(context).askEveryTime() &&
            context
                .getSystemService(
                    KeyguardManager::class.java,
                )?.let { it.isDeviceSecure && !it.isDeviceLocked } == true &&
            context.getSystemService(PowerManager::class.java)?.isInteractive == true
    }
