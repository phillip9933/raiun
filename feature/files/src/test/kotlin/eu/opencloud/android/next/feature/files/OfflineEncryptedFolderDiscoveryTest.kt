package eu.opencloud.android.next.feature.files

import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.sync.VaultLocation
import eu.opencloud.android.next.core.sync.VaultLocationKind
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.UnknownHostException

class OfflineEncryptedFolderDiscoveryTest {
    @Test fun unavailableServerPublishesSavedAndPreviouslySeenRootsInCurrentParent() =
        runBlocking {
            val saved = folderVault(path = "Projects/.vault", title = "Secure projects")
            val unsaved =
                folderVault(path = "Projects/Archive.vault", title = "Archive vault").copy(
                    remoteVaultId = "vault-archive",
                    sourceRootId = "drive-root-archive",
                    rootWebDavUrl = "https://cloud.example/dav/archive",
                )
            var immediatelyVisible = emptyList<VaultLocation>()

            val discovered =
                discoverEncryptedFolderRoots(
                    accountId = ACCOUNT,
                    driveId = DRIVE,
                    parentPath = "Projects/",
                    loadOffline = { listOf(saved) },
                    loadRemembered = {
                        listOf(
                            saved.copy(title = "Stale duplicate title"),
                            unsaved,
                            saved.copy(accountId = "another-account"),
                            saved.copy(vaultPath = "Other/.vault"),
                        )
                    },
                    loadOnline = {
                        assertEquals(
                            listOf(
                                saved.copy(
                                    title = "Stale duplicate title",
                                    offlineOnly = true,
                                    offlineUnavailable = false,
                                ),
                                unsaved.copy(offlineOnly = true, offlineUnavailable = true),
                            ),
                            immediatelyVisible,
                        )
                        throw UnknownHostException("synthetic offline server")
                    },
                    onCached = { immediatelyVisible = it },
                )

            assertEquals(
                listOf(
                    saved.copy(title = "Stale duplicate title", offlineOnly = true, offlineUnavailable = false),
                    unsaved.copy(offlineOnly = true, offlineUnavailable = true),
                ),
                discovered,
            )
            assertEquals(
                discovered,
                FileBrowserUiState().withEncryptedFolders(discovered, error = null).encryptedFolders,
            )
        }

    @Test fun savedContentsDoNotMakeMovedRootDescriptorAvailableOffline() {
        val saved = folderVault(path = "Projects/Old.vault", title = "Same vault")
        val remembered = folderVault(path = "Projects/New.vault", title = "Same vault")

        assertEquals(
            listOf(remembered.copy(offlineOnly = true, offlineUnavailable = true)),
            offlineRootAvailability(listOf(remembered), listOf(saved)),
        )
    }

    @Test fun rememberedMovedFolderRootTakesPrecedenceButCannotUnlockOldSnapshot() =
        runBlocking {
            val saved = folderVault(path = "Projects/.vault", title = "Secure projects")
            val moved = saved.copy(rootWebDavUrl = "https://cloud.example/dav/moved")

            val fallback =
                offlineRootAvailability(
                    mergeRootDescriptors(listOf(moved), listOf(saved)),
                    listOf(saved),
                )

            assertEquals(listOf(moved.copy(offlineOnly = true, offlineUnavailable = true)), fallback)
        }

    @Test fun authoritativeOnlineAbsenceDoesNotExposeStaleSnapshot() =
        runBlocking {
            val saved = folderVault(path = "Projects/.vault", title = "Former vault")

            val discovered =
                discoverEncryptedFolderRoots(
                    accountId = ACCOUNT,
                    driveId = DRIVE,
                    parentPath = "Projects",
                    loadOffline = { listOf(saved) },
                    loadOnline = { emptyList() },
                )

            assertEquals(emptyList<VaultLocation>(), discovered)
        }

    @Test fun accessDenialDoesNotFallBackToSavedRoot() {
        val saved = folderVault(path = "Projects/.vault", title = "Secure projects")

        assertThrows(OpenCloudException::class.java) {
            runBlocking {
                discoverEncryptedFolderRoots(
                    accountId = ACCOUNT,
                    driveId = DRIVE,
                    parentPath = "Projects",
                    loadOffline = { listOf(saved) },
                    loadOnline = { throw OpenCloudException(OpenCloudError.AccessDenied) },
                )
            }
        }
    }

    private fun folderVault(
        path: String,
        title: String,
    ) = VaultLocation(
        accountId = ACCOUNT,
        title = title,
        kind = VaultLocationKind.FOLDER_VAULT,
        driveId = DRIVE,
        remoteVaultId = "vault-root",
        sourceRootId = "drive-root",
        canonicalServer = "https://cloud.example",
        rootWebDavUrl = "https://cloud.example/dav/drive",
        vaultPath = path,
        isVaultRoot = true,
    )

    private companion object {
        const val ACCOUNT = "account"
        const val DRIVE = "drive"
    }
}
