package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File
import java.nio.file.Files

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class VaultRootCatalogTest {
    @Test fun descriptorsSurviveColdReopenAndRemainAccountServerAndScopeBound() =
        runBlocking {
            val root = Files.createTempDirectory("vault-root-catalog").toFile()
            try {
                var account = testAccount()
                val firstProcess =
                    VaultRootCatalog(root, { requested -> account.takeIf { it.id == requested } }, EndpointPolicy())
                val folder = location(VaultLocationKind.FOLDER_VAULT, "drive-a", "Reports/.vault", "Annual reports")
                val space = location(VaultLocationKind.SPACE_VAULT, "drive-space", "", "Projects")
                firstProcess.replaceFolderRoots(ACCOUNT, "drive-a", "Reports", listOf(folder))
                firstProcess.replaceSpaceRoots(ACCOUNT, listOf(space))

                // A new instance reads only persisted descriptors; no process-local collection is involved.
                val afterRestart =
                    VaultRootCatalog(root, { requested -> account.takeIf { it.id == requested } }, EndpointPolicy())
                assertEquals(
                    listOf(folder.copy(offlineOnly = true)),
                    afterRestart.folderRoots(ACCOUNT, "drive-a", "Reports/"),
                )
                assertEquals(listOf(space.copy(offlineOnly = true)), afterRestart.spaceRoots(ACCOUNT))
                assertTrue(
                    root.walkTopDown().filter(File::isFile).any { file ->
                        file.readText().contains("Annual reports")
                    },
                )

                assertThrows(OpenCloudException::class.java) {
                    runBlocking { afterRestart.folderRoots("another-account", "drive-a", "Reports") }
                }
                assertEquals(emptyList<VaultLocation>(), afterRestart.folderRoots(ACCOUNT, "drive-a", "Other"))

                account = account.copy(serverUrl = "https://other.example")
                assertEquals(emptyList<VaultLocation>(), afterRestart.spaceRoots(ACCOUNT))
            } finally {
                root.deleteRecursively()
            }
        }

    @Test fun authoritativeEmptyListingClearsOnlyItsScope() =
        runBlocking {
            val root = Files.createTempDirectory("vault-root-catalog-scope").toFile()
            try {
                val catalog =
                    VaultRootCatalog(
                        root,
                        { requested -> testAccount().takeIf { it.id == requested } },
                        EndpointPolicy(),
                    )
                val reports = location(VaultLocationKind.FOLDER_VAULT, "drive-a", "Reports/.vault", "Reports vault")
                val plans = location(VaultLocationKind.FOLDER_VAULT, "drive-a", "Plans/.vault", "Plans vault")
                catalog.replaceFolderRoots(ACCOUNT, "drive-a", "Reports", listOf(reports))
                catalog.replaceFolderRoots(ACCOUNT, "drive-a", "Plans", listOf(plans))

                catalog.replaceFolderRoots(ACCOUNT, "drive-a", "Reports", emptyList())

                assertEquals(emptyList<VaultLocation>(), catalog.folderRoots(ACCOUNT, "drive-a", "Reports"))
                assertEquals(listOf(plans.copy(offlineOnly = true)), catalog.folderRoots(ACCOUNT, "drive-a", "Plans"))
            } finally {
                root.deleteRecursively()
            }
        }

    @Test fun inactiveAccountCannotReadOrWriteDescriptors() =
        runBlocking {
            val root = Files.createTempDirectory("vault-root-catalog-inactive").toFile()
            try {
                val catalog = VaultRootCatalog(root, { testAccount().copy(isActive = false) }, EndpointPolicy())
                assertThrows(OpenCloudException::class.java) { runBlocking { catalog.spaceRoots(ACCOUNT) } }
                assertThrows(OpenCloudException::class.java) {
                    runBlocking { catalog.replaceSpaceRoots(ACCOUNT, emptyList()) }
                }
                Unit
            } finally {
                root.deleteRecursively()
            }
        }

    @Test fun descriptorsContainRootMetadataOnly() =
        runBlocking {
            val root = Files.createTempDirectory("vault-root-catalog-metadata").toFile()
            try {
                val catalog = VaultRootCatalog(root, { testAccount() }, EndpointPolicy())
                catalog.replaceSpaceRoots(
                    ACCOUNT,
                    listOf(location(VaultLocationKind.SPACE_VAULT, "drive-space", "", "Known space")),
                )
                val serialized =
                    root
                        .walkTopDown()
                        .filter(File::isFile)
                        .single()
                        .readText()
                val catalogJson = JSONObject(serialized)
                assertEquals(
                    setOf("version", "account", "server", "scope", "roots"),
                    catalogJson.keys().asSequence().toSet(),
                )
                val descriptor = catalogJson.getJSONArray("roots").getJSONObject(0)
                assertEquals(
                    setOf("account", "title", "kind", "drive", "vault", "sourceRoot", "server", "dav", "path"),
                    descriptor.keys().asSequence().toSet(),
                )
                assertEquals("Known space", descriptor.getString("title"))
            } finally {
                root.deleteRecursively()
            }
        }

    private fun testAccount(server: String = "https://cloud.example") =
        AccountEntity(
            ACCOUNT,
            EndpointPolicy().endpoint(server, allowQuery = false).toString(),
            "user",
            "User",
            "BASIC",
            true,
        )

    private fun location(
        kind: VaultLocationKind,
        drive: String,
        path: String,
        title: String,
    ) = VaultLocation(
        accountId = ACCOUNT,
        title = title,
        kind = kind,
        driveId = drive,
        remoteVaultId = "remote-$drive",
        sourceRootId = "source-$drive",
        canonicalServer = EndpointPolicy().endpoint("https://cloud.example", allowQuery = false).toString(),
        rootWebDavUrl = "https://cloud.example/dav/$drive",
        vaultPath = path,
        isVaultRoot = true,
    )

    private companion object {
        const val ACCOUNT = "account"
    }
}
