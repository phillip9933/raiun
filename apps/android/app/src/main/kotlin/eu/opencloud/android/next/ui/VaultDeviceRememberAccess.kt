package eu.opencloud.android.next.ui

import android.app.Application
import eu.opencloud.android.next.core.security.VaultDeviceRememberGrant
import eu.opencloud.android.next.core.security.VaultDeviceRememberStore
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.security.VaultRememberBinding
import eu.opencloud.android.next.core.security.VaultRememberChoice
import eu.opencloud.android.next.core.security.VaultUnlockKey
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

internal interface VaultDeviceRememberKey : AutoCloseable {
    val material: ByteArray

    fun isCurrent(): Boolean

    override fun close()
}

/** App-level seam so ViewModel lifecycle/race behavior can be tested without Android Keystore. */
internal interface VaultDeviceRememberAccess {
    interface Admission

    fun isSupported(): Boolean

    fun begin(
        identity: VaultIdentity,
        binding: VaultRememberBinding,
    ): Admission?

    fun remember(
        admission: Admission?,
        identity: VaultIdentity,
        binding: VaultRememberBinding,
        verifiedKeyMaterial: ByteArray,
        permit: () -> Boolean,
    ): Boolean

    fun restore(
        identity: VaultIdentity,
        binding: VaultRememberBinding,
        permit: () -> Boolean,
    ): VaultDeviceRememberKey?

    fun choice(identity: VaultIdentity): VaultRememberChoice?

    fun hasRemembered(identity: VaultIdentity): Boolean

    fun decline(identity: VaultIdentity)

    fun forget(identity: VaultIdentity)
}

internal class AndroidVaultDeviceRememberAccess(
    application: Application,
) : VaultDeviceRememberAccess {
    private val store = VaultDeviceRememberStore(application)

    private class StoreAdmission(
        val grant: VaultDeviceRememberGrant,
    ) : VaultDeviceRememberAccess.Admission

    private class StoreKey(
        private val key: VaultUnlockKey,
    ) : VaultDeviceRememberKey {
        override val material get() = key.material

        override fun isCurrent() = key.isCurrent()

        override fun close() = key.close()
    }

    override fun isSupported() = store.isSupported()

    override fun begin(
        identity: VaultIdentity,
        binding: VaultRememberBinding,
    ): VaultDeviceRememberAccess.Admission? = store.begin(identity, binding)?.let(::StoreAdmission)

    override fun remember(
        admission: VaultDeviceRememberAccess.Admission?,
        identity: VaultIdentity,
        binding: VaultRememberBinding,
        verifiedKeyMaterial: ByteArray,
        permit: () -> Boolean,
    ): Boolean =
        store.remember(
            (admission as? StoreAdmission)?.grant,
            identity,
            binding,
            verifiedKeyMaterial,
            permit,
        )

    override fun restore(
        identity: VaultIdentity,
        binding: VaultRememberBinding,
        permit: () -> Boolean,
    ): VaultDeviceRememberKey? = store.restore(identity, binding, permit)?.let(::StoreKey)

    override fun choice(identity: VaultIdentity) = store.choice(identity)

    override fun hasRemembered(identity: VaultIdentity) = store.hasRemembered(identity)

    override fun decline(identity: VaultIdentity) = store.decline(identity)

    override fun forget(identity: VaultIdentity) = store.forget(identity)
}

/** Runtime adapters grouped to keep the ViewModel constructor focused on its core dependencies. */
internal class VaultViewModelAdapters(
    application: Application,
    val uploadPollReady: (android.system.StructPollfd, Int) -> Boolean = { descriptor, timeout ->
        android.system.Os.poll(arrayOf(descriptor), timeout) > 0
    },
    val deviceRemember: VaultDeviceRememberAccess = AndroidVaultDeviceRememberAccess(application),
)

/** Owns a copied secret across queued coroutine cancellation as well as execution completion. */
internal fun launchWithOwnedMaterial(
    scope: CoroutineScope,
    material: ByteArray,
    block: suspend () -> Unit,
): Job {
    val job =
        scope.launch {
            try {
                block()
            } finally {
                material.fill(0)
            }
        }
    job.invokeOnCompletion { material.fill(0) }
    return job
}

/** Process-local ordering fence so a replacement route cannot restore ahead of an explicit-lock IO write. */
internal object VaultDeviceRememberRevocations {
    internal class Ticket internal constructor(
        val identity: VaultIdentity,
        internal val predecessor: Deferred<Boolean>?,
        internal val completion: CompletableDeferred<Boolean>,
    )

    private val monitor = Any()
    private val pending = mutableMapOf<VaultIdentity, CompletableDeferred<Boolean>>()

    fun begin(identity: VaultIdentity): Ticket =
        synchronized(monitor) {
            val completion = CompletableDeferred<Boolean>()
            Ticket(identity, pending.put(identity, completion), completion)
        }

    suspend fun await(identity: VaultIdentity): Boolean? {
        val completion = synchronized(monitor) { pending[identity] } ?: return null
        return completion.await()
    }

    suspend fun awaitPredecessor(ticket: Ticket) {
        ticket.predecessor?.await()
    }

    fun finish(
        ticket: Ticket,
        succeeded: Boolean,
    ) {
        ticket.completion.complete(succeeded)
        if (succeeded) {
            synchronized(monitor) {
                if (pending[ticket.identity] === ticket.completion) pending.remove(ticket.identity)
            }
        }
    }

    fun block(identity: VaultIdentity) {
        synchronized(monitor) {
            val current = pending[identity]
            if (current == null || current.isCompleted) {
                pending[identity] = CompletableDeferred<Boolean>().also { it.complete(false) }
            }
        }
    }
}
