package eu.opencloud.android.next.core.security

import android.util.AtomicFile
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.nio.file.Files
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

@RunWith(RobolectricTestRunner::class)
class VaultDeviceRememberStoreTest {
    @get:Rule val temporaryFolder = TemporaryFolder()

    private val identity = VaultIdentity("account-id", "https://cloud.example", "drive", "vault")
    private val otherIdentity = VaultIdentity("account-id", "https://cloud.example", "drive", "other-vault")
    private val binding = VaultRememberBinding("0123456789abcdef0123456789abcdef", "a".repeat(64))
    private val changedBinding = binding.copy(incarnation = "fedcba9876543210fedcba9876543210")
    private val keyBytes = ByteArray(80) { it.toByte() }
    private lateinit var crypto: FakeCrypto
    private lateinit var directory: File
    private var askEveryTime = false
    private var secure = true
    private var unlocked = true
    private var appAllowed = true
    private var permitted = true
    private var aliasSequence = 0

    private fun newStore(
        failpoint: (VaultDeviceRememberFailpoint, ByteArray?) -> Unit = { _, _ -> },
        aliasFactory: (VaultIdentity) -> String = { requested ->
            "raiun_vault_device_v1_${requested.hashForRemember()}_${"%016x".format(aliasSequence++)}"
        },
    ): VaultDeviceRememberStore =
        VaultDeviceRememberStore(
            directory,
            crypto,
            { askEveryTime },
            { secure },
            { secure && unlocked && appAllowed },
            VaultDeviceRememberTestHooks(aliasFactory, failpoint),
        )

    @org.junit.Before fun setup() {
        directory = temporaryFolder.newFolder("remember-store")
        crypto = FakeCrypto()
        askEveryTime = false
        secure = true
        unlocked = true
        appAllowed = true
        permitted = true
        aliasSequence = 0
    }

    @Test fun persistsAcrossStoreInstancesAndReturnsOnlyCallerOwnedMaterial() {
        val store = newStore()
        val callerMaterial = keyBytes.copyOf()
        val grant = requireNotNull(store.begin(identity, binding))
        assertTrue(store.remember(grant, identity, binding, callerMaterial) { permitted })
        assertArrayEquals(keyBytes, callerMaterial)
        assertEquals(VaultRememberChoice.REMEMBERED, newStore().choice(identity))

        val restored = requireNotNull(newStore().restore(identity, binding) { permitted })
        assertArrayEquals(keyBytes, restored.material)
        assertTrue(restored.isCurrent())
        restored.close()
        assertArrayEquals(ByteArray(80), restored.material)
    }

    @Test fun accountIncarnationAndExactVaultBindingAreRequired() {
        val store = newStore()
        assertTrue(store.remember(requireNotNull(store.begin(identity, binding)), identity, binding, keyBytes) { true })
        assertNull(store.restore(identity, changedBinding) { true })
        assertNull(store.restore(otherIdentity, binding) { true })
    }

    @Test fun capturedGrantCanCommitThroughAnotherStoreInstanceAtSameDirectory() {
        val first = newStore()
        val grant = requireNotNull(first.begin(identity, binding))
        val second = newStore()
        assertTrue(second.remember(grant, identity, binding, keyBytes) { true })
        val restored = requireNotNull(first.restore(identity, binding) { true })
        assertArrayEquals(keyBytes, restored.material)
        restored.close()
    }

    @Test fun strictModeAndLockedOrInsecureDeviceDenyAdmissionAndRestore() {
        val store = newStore()
        val grant = requireNotNull(store.begin(identity, binding))
        assertTrue(store.remember(grant, identity, binding, keyBytes) { true })
        unlocked = false
        assertNull(store.begin(identity, binding))
        assertNull(store.restore(identity, binding) { true })
        unlocked = true
        secure = false
        assertFalse(store.isSupported())
        assertNull(store.restore(identity, binding) { true })
        secure = true
        askEveryTime = true
        assertNull(store.begin(identity, binding))
        assertNull(store.restore(identity, binding) { true })
    }

    @Test fun providerAndCredentialPermitFailuresDoNotWriteARecord() {
        val store = newStore()
        crypto.acceptable = false
        val grant = requireNotNull(store.begin(identity, binding))
        assertFalse(store.remember(grant, identity, binding, keyBytes) { true })
        assertFalse(store.hasRemembered(identity))

        crypto.acceptable = true
        val next = requireNotNull(store.begin(identity, binding))
        permitted = false
        assertFalse(store.remember(next, identity, binding, keyBytes) { permitted })
        assertFalse(store.hasRemembered(identity))
    }

    @Test fun failedPostCommitRevocationDeletesNewKeyAndReportsUnknown() {
        val aliasSuffix = "${"%016x".format(0)}"
        val expectedAlias = "raiun_vault_device_v1_${identity.hashForRemember()}_$aliasSuffix"
        val store =
            newStore(
                failpoint = { point, _ ->
                    if (point == VaultDeviceRememberFailpoint.AFTER_REMEMBERED_CHOICE_COMMIT) permitted = false
                    if (point ==
                        VaultDeviceRememberFailpoint.BEFORE_POST_COMMIT_REVOCATION_WRITE
                    ) {
                        error("synthetic ledger failure")
                    }
                },
            )
        val grant = requireNotNull(store.begin(identity, binding))

        org.junit.Assert.assertThrows(VaultDeviceRememberOutcomeUnknownException::class.java) {
            store.remember(grant, identity, binding, keyBytes) { permitted }
        }
        assertTrue(expectedAlias !in crypto.aliases())
        assertFalse(store.hasRemembered(identity))
        assertNull(store.restore(identity, binding) { true })
        assertEquals(VaultRememberChoice.REMEMBERED, store.choice(identity))
    }

    @Test fun failureAfterDurablePostCommitRevocationLeavesNoRestorableKey() {
        val store =
            newStore(
                failpoint = { point, _ ->
                    if (point == VaultDeviceRememberFailpoint.AFTER_REMEMBERED_CHOICE_COMMIT) permitted = false
                    if (point ==
                        VaultDeviceRememberFailpoint.AFTER_POST_COMMIT_REVOCATION_WRITE
                    ) {
                        error("synthetic post-revocation failure")
                    }
                },
            )
        val grant = requireNotNull(store.begin(identity, binding))

        org.junit.Assert.assertThrows(VaultDeviceRememberOutcomeUnknownException::class.java) {
            store.remember(grant, identity, binding, keyBytes) { permitted }
        }
        assertNull(store.choice(identity))
        assertFalse(store.hasRemembered(identity))
        assertNull(store.restore(identity, binding) { true })
        assertTrue(crypto.aliases().none { it.startsWith("raiun_vault_device_v1_${identity.hashForRemember()}_") })
    }

    @Test fun postDecryptExceptionWipesOwnedPlaintextBeforeReturningUnavailable() {
        val writer = newStore()
        assertTrue(
            writer.remember(requireNotNull(writer.begin(identity, binding)), identity, binding, keyBytes) { true },
        )
        var observed: ByteArray? = null
        val failingRestore =
            newStore(failpoint = { point, material ->
                if (point == VaultDeviceRememberFailpoint.AFTER_DECRYPTION) {
                    observed = material
                    error("synthetic post-decrypt ledger failure")
                }
            })

        assertNull(failingRestore.restore(identity, binding) { true })
        assertArrayEquals(ByteArray(80), requireNotNull(observed))
    }

    @Test fun refusedAliasCollisionDoesNotDeletePreexistingKey() {
        val collision = "raiun_vault_device_v1_${identity.hashForRemember()}_${"%016x".format(9)}"
        val existing = SecretKeySpec(ByteArray(32) { 7 }, "AES")
        crypto.keys[collision] = existing
        val store = newStore(aliasFactory = { collision })
        val grant = requireNotNull(store.begin(identity, binding))

        assertFalse(store.remember(grant, identity, binding, keyBytes) { true })
        assertSame(existing, crypto.keys[collision])
        assertFalse(store.hasRemembered(identity))
    }

    @Test fun forgetDeclineAndStrictPolicyFenceCapturedAndRestoredKeys() {
        val first = newStore()
        val lateGrant = requireNotNull(first.begin(identity, binding))
        assertTrue(first.remember(lateGrant, identity, binding, keyBytes) { true })
        val restored = requireNotNull(first.restore(identity, binding) { true })

        val second = newStore()
        second.forget(identity)
        assertFalse(restored.isCurrent())
        assertFalse(first.remember(lateGrant, identity, binding, keyBytes) { true })
        assertNull(first.restore(identity, binding) { true })

        val newGrant = requireNotNull(first.begin(identity, binding))
        assertTrue(first.remember(newGrant, identity, binding, keyBytes) { true })
        first.decline(identity)
        assertEquals(VaultRememberChoice.DECLINED, second.choice(identity))
        assertFalse(second.hasRemembered(identity))

        val declinedGrant = requireNotNull(first.begin(identity, binding))
        assertTrue(first.remember(declinedGrant, identity, binding, keyBytes) { true })
        second.decline(otherIdentity)
        first.changeAskEveryTime(true) { askEveryTime = true }
        assertNull(second.begin(identity, binding))
        assertNull(second.restore(identity, binding) { true })
        assertNull(second.choice(identity))
        assertEquals(VaultRememberChoice.DECLINED, second.choice(otherIdentity))
    }

    @Test fun accountRemovalFencesOtherInstancesAndRemovesOnlyThatAccount() {
        val first = newStore()
        val otherAccount = identity.copy(accountId = "another-account")
        assertTrue(first.remember(requireNotNull(first.begin(identity, binding)), identity, binding, keyBytes) { true })
        assertTrue(
            first.remember(
                requireNotNull(first.begin(otherAccount, binding)),
                otherAccount,
                binding,
                keyBytes,
            ) { true },
        )
        val late = requireNotNull(first.begin(identity, binding))

        newStore().forgetAccount(identity.accountId)
        assertFalse(first.remember(late, identity, binding, keyBytes) { true })
        assertNull(first.restore(identity, binding) { true })
        first.restore(otherAccount, binding) { true }?.close()
        assertTrue(first.hasRemembered(otherAccount))
    }

    @Test fun corruptedCiphertextAndWrongEnvelopeIdentityFailClosed() {
        val store = newStore()
        assertTrue(store.remember(requireNotNull(store.begin(identity, binding)), identity, binding, keyBytes) { true })
        val record = directory.listFiles()!!.single { it.name.endsWith(".record") }
        val contents = AtomicFile(record).openRead().use { it.readBytes() }
        contents[contents.lastIndex] = (contents.last().toInt() xor 0x01).toByte()
        val atomic = AtomicFile(record)
        val output = atomic.startWrite()
        output.write(contents)
        atomic.finishWrite(output)
        contents.fill(0)
        assertNull(store.restore(identity, binding) { true })
    }

    @Test fun symlinkedRecordIsRejectedWithoutFollowingItsTarget() {
        val store = newStore()
        assertTrue(store.remember(requireNotNull(store.begin(identity, binding)), identity, binding, keyBytes) { true })
        val target = temporaryFolder.newFile("outside.record")
        val record = File(directory, "remember_${identity.hashForRemember()}.record")
        AtomicFile(record).delete()
        Files.createSymbolicLink(record.toPath(), target.toPath())
        assertNull(store.restore(identity, binding) { true })
        assertTrue(target.exists())
    }

    @Test fun resetAndForgetAllRotateDurableEpochs() {
        val store = newStore()
        val grant = requireNotNull(store.begin(identity, binding))
        assertTrue(store.remember(grant, identity, binding, keyBytes) { true })
        store.resetChoice(identity)
        assertFalse(store.remember(grant, identity, binding, keyBytes) { true })
        assertNull(store.choice(identity))

        val secondGrant = requireNotNull(store.begin(identity, binding))
        assertTrue(store.remember(secondGrant, identity, binding, keyBytes) { true })
        val oldGrantForOther = requireNotNull(store.begin(otherIdentity, binding))
        store.forgetAll()
        assertFalse(store.remember(oldGrantForOther, otherIdentity, binding, keyBytes) { true })
        assertTrue(store.identities().isEmpty())
    }

    internal class FakeCrypto : VaultDeviceRememberCrypto {
        val keys = linkedMapOf<String, SecretKey>()
        var acceptable = true

        override fun isPlatformSupported() = true

        override fun create(alias: String): SecretKey {
            check(alias !in keys) { "Refusing to adopt an existing alias." }
            return SecretKeySpec(ByteArray(32) { alias.hashCode().toByte() }, "AES").also { keys[alias] = it }
        }

        override fun load(alias: String): SecretKey? = keys[alias]

        override fun aliases(): Set<String> = keys.keys.toSet()

        override fun delete(alias: String) {
            keys.remove(alias)
        }

        override fun isAcceptable(key: SecretKey) = acceptable && key.encoded?.size == 32
    }
}
