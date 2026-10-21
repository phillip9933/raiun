package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MixedBrowserEntryTest {
    @Test
    fun `mixed list hides stale ordinary resources matching encrypted root id or path`() {
        val byId = resource("vault-root-id", "Legacy vault name")
        val byPath = resource("stale-dav-id", "Old path", path = "folders/.vault/")
        val ordinary = resource("ordinary-id", "Documents")

        val entries =
            mixedBrowserEntries(
                resources = listOf(byId, byPath, ordinary),
                encrypted = listOf(vaultLocation()),
                criterion = BrowserSortCriterion.Name,
                ascending = true,
            )

        assertEquals(listOf("Documents", "Secure vault"), entries.map { it.name })
        assertEquals(listOf(ordinary), entries.mapNotNull { it.resource })
        assertEquals(listOf(vaultLocation()), entries.mapNotNull { it.encrypted })
    }

    @Test
    fun `encrypted discovery clears matching selection and action but keeps unrelated selection`() {
        val byId = resource("vault-root-id", "Legacy vault name")
        val byPath = resource("stale-dav-id", "Old path", path = "folders/.vault/")
        val ordinary = resource("ordinary-id", "Documents")
        val state =
            FileBrowserUiState(
                resources = listOf(byId, byPath, ordinary),
                selectedIds = setOf(byId.selectionKey, byPath.selectionKey, ordinary.selectionKey),
                actionResource = byId,
            )

        val updated = state.withEncryptedFolders(listOf(vaultLocation()), error = null)

        assertEquals(setOf(ordinary.selectionKey), updated.selectedIds)
        assertNull(updated.actionResource)
    }

    private fun resource(
        id: String,
        name: String,
        path: String = name,
    ) = ResourceEntity(
        accountId = ACCOUNT,
        spaceId = DRIVE,
        remoteId = id,
        parentId = null,
        path = path,
        name = name,
        kind = ResourceKind.FOLDER,
        mimeType = null,
        sizeBytes = 0,
        eTag = null,
        modifiedAtEpochMillis = 0,
        createdAtEpochMillis = 0,
    )

    private fun vaultLocation() =
        VaultLocation(
            accountId = ACCOUNT,
            title = "Secure vault",
            kind = VaultLocationKind.FOLDER_VAULT,
            driveId = DRIVE,
            remoteVaultId = "vault-root-id",
            sourceRootId = "source-root-id",
            canonicalServer = "https://cloud.example",
            rootWebDavUrl = "https://cloud.example/dav/root",
            vaultPath = "folders/.vault",
            isVaultRoot = true,
        )

    private companion object {
        const val ACCOUNT = "account"
        const val DRIVE = "drive"
    }
}
