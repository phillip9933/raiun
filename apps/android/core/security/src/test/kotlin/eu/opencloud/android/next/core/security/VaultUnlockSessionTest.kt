package eu.opencloud.android.next.core.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class VaultUnlockSessionTest {
    private val identity = VaultIdentity("account", "https://cloud.example", "drive", "vault")
    private val key = ByteArray(80) { (it + 1).toByte() }

    @Test fun copiesBothDirectionsAndWipesOwnedMaterialOnForget() {
        val cache = VerifiedVaultKeyCache()
        val session = VaultUnlockSession(cache) { true }
        val input = key.copyOf()
        session.remember(session.beginUnlock(), identity, "account-row", input) { true }
        val owned = ownedMaterial(cache, identity)
        input.fill(0)
        val first = requireNotNull(session.reuse(identity, "account-row"))
        assertArrayEquals(key, first.material)
        first.material.fill(0)
        first.close()
        assertFalse(first.isCurrent())
        assertArrayEquals(ByteArray(80), first.material)
        val second = requireNotNull(session.reuse(identity, "account-row"))
        assertArrayEquals(key, second.material)
        session.forget(identity)
        assertArrayEquals(ByteArray(80), owned)
        assertFalse(second.isCurrent())
        second.close()
        assertNull(session.reuse(identity, "account-row"))
    }

    @Test fun everyIdentityDimensionAndAccountSnapshotMustMatch() {
        val session = VaultUnlockSession(VerifiedVaultKeyCache()) { true }
        session.remember(session.beginUnlock(), identity, "initial-row", key) { true }
        listOf(
            identity.copy(accountId = "other"),
            identity.copy(canonicalServer = "https://other.example"),
            identity.copy(driveId = "other"),
            identity.copy(remoteVaultId = "other"),
        ).forEach { assertNull(session.reuse(it, "initial-row")) }
        assertNotNull(session.reuse(identity, "initial-row")?.also { it.close() })
        assertNull(session.reuse(identity, "changed-row"))
        assertNull(session.reuse(identity, "initial-row"))
    }

    @Test fun capacityEvictsAndWipesOldestWithoutLosingOtherLocation() {
        val cache = VerifiedVaultKeyCache(2)
        val session = VaultUnlockSession(cache) { true }
        session.remember(session.beginUnlock(), identity, "row", key) { true }
        val owned = ownedMaterial(cache, identity)
        val second = identity.copy(remoteVaultId = "second")
        val third = identity.copy(remoteVaultId = "third")
        session.remember(session.beginUnlock(), second, "row", key) { true }
        session.remember(session.beginUnlock(), third, "row", key) { true }
        assertArrayEquals(ByteArray(80), owned)
        assertNull(session.reuse(identity, "row"))
        assertNotNull(session.reuse(second, "row")?.also { it.close() })
        assertNotNull(session.reuse(third, "row")?.also { it.close() })
        assertThrows(IllegalArgumentException::class.java) { VerifiedVaultKeyCache(9) }
    }

    @Test fun lockOrPolicyChangeRejectsLateCompletionAndDoesNotReviveAfterUnlock() {
        val session = VaultUnlockSession(VerifiedVaultKeyCache()) { true }
        val oldGrant = session.beginUnlock()
        session.remember(oldGrant, identity, "row", key) { true }
        val reused = requireNotNull(session.reuse(identity, "row"))
        session.clear()
        session.remember(oldGrant, identity, "row", key) { true }
        assertFalse(reused.isCurrent())
        reused.close()
        assertNull(session.reuse(identity, "row"))
        session.remember(session.beginUnlock(), identity, "row", key) { true }
        assertNotNull(session.reuse(identity, "row")?.also { it.close() })
    }

    @Test fun observingLockedOrUnavailableDevicePermanentlyWipesExistingGrant() {
        var available = true
        val cache = VerifiedVaultKeyCache()
        val session = VaultUnlockSession(cache) { available }
        session.remember(session.beginUnlock(), identity, "row", key) { true }
        val owned = ownedMaterial(cache, identity)
        val reused = requireNotNull(session.reuse(identity, "row"))
        available = false
        assertFalse(reused.isCurrent())
        assertArrayEquals(ByteArray(80), owned)
        available = true
        assertNull(session.reuse(identity, "row"))
        reused.close()
    }

    @Test fun invalidationDuringAvailabilityCheckCannotCreateNewGenerationGrant() {
        val cache = VerifiedVaultKeyCache()
        val session =
            VaultUnlockSession(cache) {
                cache.invalidate {}
                true
            }
        assertNull(session.beginUnlock())
    }

    @Test fun credentialRevocationWipesOnlyItsAccountAndRejectsPendingGrant() {
        var active = true
        val session = VaultUnlockSession(VerifiedVaultKeyCache()) { true }
        val other = identity.copy(accountId = "other")
        session.remember(session.beginUnlock(), identity, "row", key) { active }
        session.remember(session.beginUnlock(), other, "row", key) { true }
        val pending = session.beginUnlock()
        active = false
        assertNull(session.reuse(identity, "row"))
        session.forgetAccount(identity.accountId)
        session.remember(pending, identity, "row", key) { true }
        assertNull(session.reuse(identity, "row"))
        assertNotNull(session.reuse(other, "row")?.also { it.close() })
    }

    @Test fun failedPolicyCommitStillWipesAndRotatesAndUnavailableChecksFailClosed() {
        val cache = VerifiedVaultKeyCache()
        val session = VaultUnlockSession(cache) { true }
        val pending = session.beginUnlock()
        session.remember(pending, identity, "row", key) { true }
        assertThrows(IllegalStateException::class.java) { cache.invalidate { error("synthetic commit failure") } }
        session.remember(pending, identity, "row", key) { true }
        assertNull(session.reuse(identity, "row"))
        assertNull(VaultUnlockSession(cache) { error("synthetic unavailable service") }.beginUnlock())
        session.remember(session.beginUnlock(), identity, "row", ByteArray(81)) { true }
        assertNull(session.reuse(identity, "row"))
    }

    @Test fun rememberReturnsTypedAdmissionReasonsWithoutChangingGuards() {
        var available = true
        val cache = VerifiedVaultKeyCache()
        val session = VaultUnlockSession(cache) { available }

        assertEquals(
            VaultUnlockRememberResult.REMEMBERED,
            session.remember(session.beginUnlock(), identity, "row", key) { true },
        )
        assertEquals(VaultUnlockRememberResult.MISSING_GRANT, session.remember(null, identity, "row", key) { true })

        val lateGrant = requireNotNull(session.beginUnlock())
        session.clear()
        assertEquals(
            VaultUnlockRememberResult.STALE_GRANT,
            session.remember(lateGrant, identity, "row", key) { true },
        )

        assertEquals(
            VaultUnlockRememberResult.CREDENTIAL_REVOKED,
            session.remember(session.beginUnlock(), identity, "row", key) { false },
        )
        assertEquals(
            VaultUnlockRememberResult.INVALID_MATERIAL,
            session.remember(session.beginUnlock(), identity, "row", ByteArray(79)) { true },
        )

        val grantBeforeUnavailable = requireNotNull(session.beginUnlock())
        available = false
        assertEquals(
            VaultUnlockRememberResult.UNAVAILABLE,
            session.remember(
                grantBeforeUnavailable,
                identity,
                "row",
                key,
            ) {
                true
            },
        )
        available = true
        assertNull(session.reuse(identity, "row"))
    }

    // Inspect the owned byte array to prove disposal, without adding production key-inspection APIs.
    private fun ownedMaterial(
        cache: VerifiedVaultKeyCache,
        identity: VaultIdentity,
    ): ByteArray {
        val entriesField = cache.javaClass.getDeclaredField("entries").also { it.isAccessible = true }
        val entry = requireNotNull((entriesField.get(cache) as Map<*, *>)[identity])
        return entry.javaClass
            .getDeclaredField("material")
            .also { it.isAccessible = true }
            .get(entry) as ByteArray
    }
}
