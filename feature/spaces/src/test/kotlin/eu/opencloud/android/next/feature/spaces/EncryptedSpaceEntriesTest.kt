package eu.opencloud.android.next.feature.spaces

import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.UnknownHostException

class EncryptedSpaceEntriesTest {
    @Test fun unavailableServerKeepsOnlyAccountScopedSavedEncryptedSpaces() =
        runBlocking {
            val saved = vault("saved", "Saved encrypted space").copy(offlineOnly = false)
            val unsaved = vault("seen", "Previously seen space")
            var immediatelyVisible = emptyList<VaultLocation>()
            var disabledLookupCount = 0

            val result =
                discoverEncryptedSpaceRoots(
                    accountId = "account",
                    loadOffline = { listOf(saved, saved.copy(accountId = "other-account")) },
                    loadRemembered = { listOf(saved.copy(title = "Stale title"), unsaved) },
                    loadAvailable = { throw UnknownHostException("synthetic offline server") },
                    loadDisabled = {
                        disabledLookupCount++
                        emptyList()
                    },
                    onCached = { immediatelyVisible = it },
                    removeOffline = { error("No authoritative disabled result is available offline") },
                )

            assertEquals(
                listOf(
                    saved.copy(title = "Stale title", offlineOnly = true, offlineUnavailable = false),
                    unsaved.copy(offlineOnly = true, offlineUnavailable = true),
                ),
                result.locations,
            )
            assertEquals(result.locations, immediatelyVisible)
            assertEquals(
                listOf("Previously seen space", "Stale title"),
                mergedSpaceEntries(emptyList(), result.locations).map { it.title },
            )
            assertFalse(result.hadFailure)
            assertEquals(0, disabledLookupCount)
        }

    @Test fun savedContentsDoNotMakeMovedSpaceDescriptorAvailableOffline() {
        val saved = vault("moved", "Same space").copy(vaultPath = "old-root")
        val remembered = vault("moved", "Same space").copy(vaultPath = "new-root")

        assertEquals(
            listOf(remembered.copy(offlineOnly = true, offlineUnavailable = true)),
            offlineSpaceAvailability(listOf(remembered), listOf(saved)),
        )
    }

    @Test fun accessDeniedDoesNotExposeSavedEncryptedSpace() {
        val saved = vault("saved", "Saved encrypted space")

        assertThrows(OpenCloudException::class.java) {
            runBlocking {
                discoverEncryptedSpaceRoots(
                    accountId = "account",
                    loadOffline = { listOf(saved) },
                    loadAvailable = { throw OpenCloudException(OpenCloudError.AccessDenied) },
                    loadDisabled = { error("Disabled lookup is skipped after denied access") },
                    removeOffline = { error("No authoritative disabled result is available") },
                )
            }
        }
    }

    @Test fun successfulOnlineDiscoveryDoesNotExposeStaleSavedSpace() =
        runBlocking {
            val saved = vault("saved", "Former encrypted space")

            val result =
                discoverEncryptedSpaceRoots(
                    accountId = "account",
                    loadOffline = { listOf(saved) },
                    loadAvailable = { emptyList() },
                    loadDisabled = { emptyList() },
                    removeOffline = { error("No disabled snapshot expected") },
                )

            assertEquals(emptyList<VaultLocation>(), result.locations)
        }

    @Test fun authoritativeDisabledSpaceRemovesItsOfflineSnapshot() =
        runBlocking {
            val saved = vault("disabled", "Disabled encrypted space")
            var removed = false

            val result =
                discoverEncryptedSpaceRoots(
                    accountId = "account",
                    loadOffline = { listOf(saved) },
                    loadAvailable = { emptyList() },
                    loadDisabled = { listOf(saved.copy(isDisabled = true)) },
                    removeOffline = { removed = true },
                )

            assertTrue(removed)
            assertEquals(listOf(saved.copy(isDisabled = true)), result.locations)
        }

    @Test fun encryptedAndOrdinarySpacesSortTogetherButRemainDistinct() {
        val entries =
            mergedSpaceEntries(
                spaces = listOf(space("plain", "Zebra"), space("ordinary", "Alpine")),
                encryptedSpaces = listOf(vault("encrypted", "Betty")),
            )

        assertEquals(listOf("Alpine", "Betty", "Zebra"), entries.map { it.title })
        assertTrue(entries[0] is SpaceListEntry.Plain)
        assertTrue(entries[1] is SpaceListEntry.Encrypted)
        assertEquals(3, entries.map { it.key }.distinct().size)
    }

    @Test fun encryptedSpaceReplacesStalePlainCardForSameDrive() {
        val entries =
            mergedSpaceEntries(
                spaces = listOf(space("converted", "Old plain name"), space("other", "Other")),
                encryptedSpaces = listOf(vault("converted", "Locked name")),
            )

        assertEquals(listOf("Locked name", "Other"), entries.map { it.title })
        assertTrue(entries[0] is SpaceListEntry.Encrypted)
        assertEquals(2, entries.size)
    }

    private fun space(
        id: String,
        name: String,
    ) = SpaceEntity(
        accountId = "account",
        driveId = id,
        name = name,
        type = "project",
        description = null,
        ownerName = null,
        rootId = id,
        rootWebDavUrl = null,
        rootETag = null,
        quotaBytes = null,
    )

    private fun vault(
        id: String,
        name: String,
    ) = VaultLocation(
        accountId = "account",
        title = name,
        kind = VaultLocationKind.SPACE_VAULT,
        driveId = id,
        remoteVaultId = "storage$id!$id",
        sourceRootId = "storage$id",
        canonicalServer = "https://cloud.example",
        rootWebDavUrl = "https://cloud.example/dav/$id",
        vaultPath = "",
        isVaultRoot = true,
    )
}
