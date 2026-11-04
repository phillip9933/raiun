package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.file.Files

@RunWith(RobolectricTestRunner::class)
class VaultOfflineDirectoryTest {
    private lateinit var root: File
    private lateinit var store: VaultOfflineStore
    private lateinit var account: AccountEntity
    private lateinit var location: VaultLocation
    private lateinit var identity: VaultIdentity
    private var currentAccount: AccountEntity? = null
    private val material = ByteArray(80) { it.toByte() }

    @Before fun setUp() {
        root = Files.createTempDirectory("vault-offline-test").toFile()
        val server = EndpointPolicy(true).endpoint("https://example.test/", allowQuery = false).toString()
        account = AccountEntity("account", server, "user", "User", "BASIC", false)
        currentAccount = account
        location =
            VaultLocation(
                accountId = account.id,
                title = "Secret.vault",
                kind = VaultLocationKind.FOLDER_VAULT,
                driveId = "drive",
                remoteVaultId = "vault-id",
                sourceRootId = "root-id",
                canonicalServer = server,
                rootWebDavUrl = "https://example.test/dav/files/",
                vaultPath = "Secret.vault",
                isVaultRoot = true,
            )
        identity = VaultIdentity(account.id, server, "drive", "vault-id")
        store =
            VaultOfflineStore(
                root,
                { currentAccount },
                { { true } },
                EndpointPolicy(true),
                { VaultOfflineTestCipher() },
                durability = jvmOfflineDurability(root),
            )
    }

    @After fun tearDown() {
        root.deleteRecursively()
        material.fill(0)
    }

    @Test fun pagedOfflineDirectoryReauthenticatesManifestAndInvalidatesOldSnapshots() =
        runBlocking {
            repeat(131) { number -> store.pinDirectory(identity, location, "Secret.vault/opaque-$number", material) }
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            try {
                val old = session.openDirectory()
                assertEquals(131L, old.totalCount)
                val first = old.page(0, 128)
                val second = old.page(first.size.toLong(), 128)
                assertEquals(128, first.size)
                assertEquals(3, second.size)
                assertEquals(131, (first + second).map(VaultFolder::encryptedPath).toSet().size)
                store.pinDirectory(identity, location, "Secret.vault/new-child", material)
                assertThrows(OpenCloudException::class.java) { runBlocking { old.page() } }
                session.openDirectory().use { fresh -> assertEquals(132L, fresh.totalCount) }
            } finally {
                session.close()
            }
            assertTrue(root.walkTopDown().none { it.name.startsWith("vault-directory-") })
        }

    @Test fun pagedOfflineAccessRejectsCorruptCurrentManifestAndAccountSwitch() =
        runBlocking {
            store.pinDirectory(identity, location, "Secret.vault/child", material)
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            try {
                val snapshot = session.openDirectory()
                assertEquals(1, snapshot.page().size)
                val manifestFile = root.walkTopDown().single { it.name == "manifest.enc" }
                val saved = manifestFile.readBytes()
                val damaged = saved.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
                manifestFile.writeBytes(damaged)
                assertThrows(OpenCloudException::class.java) { runBlocking { snapshot.page() } }
                assertThrows(OpenCloudException::class.java) { runBlocking { session.openDirectory() } }
                manifestFile.writeBytes(saved)
                saved.fill(0)
                damaged.fill(0)
                val replacement = session.openDirectory()
                currentAccount = account.copy(id = "another-account")
                assertThrows(OpenCloudException::class.java) { runBlocking { replacement.page() } }
            } finally {
                session.close()
            }
            Unit
        }

    @Test fun pagedOfflineHiddenVisibilityCountsOnlyEligibleChildrenBeforePaging() =
        runBlocking {
            repeat(131) { number ->
                val name = if (number % 2 == 0) ".hidden-$number" else "visible-$number"
                store.pinDirectory(identity, location, "Secret.vault/$name", material)
            }
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            try {
                session.openDirectory().use { visible ->
                    assertEquals(65L, visible.totalCount)
                    val first = visible.page(0, 43)
                    val second = visible.page(first.size.toLong(), 43)
                    assertEquals(43, first.size)
                    assertEquals(22, second.size)
                    assertTrue((first + second).none { it.name.startsWith('.') })
                }
                session.openDirectory(showHidden = true).use { all ->
                    assertEquals(131L, all.totalCount)
                    val first = all.page(0, 128)
                    val second = all.page(first.size.toLong(), 128)
                    assertEquals(128, first.size)
                    assertEquals(3, second.size)
                    assertEquals(66, (first + second).count { it.name.startsWith('.') })
                }
            } finally {
                session.close()
            }
        }

    @Test fun boundedOfflineStatusMatchesOpaqueVersionsWithoutDecryptingChildNames() =
        runBlocking {
            val encrypted = fakeCiphertext(byteArrayOf(1))
            val cached = (0 until 140).map { fileEntry("opaque-$it", encrypted.size.toLong()) }
            cached.forEach { entry -> store.pinFile(identity, location, entry, material) { it.write(encrypted) } }
            var nameDecryptions = 0
            val controlled =
                VaultOfflineStore(root, { currentAccount }, { { true } }, EndpointPolicy(true), {
                    VaultOfflineTestCipher(onName = {
                        nameDecryptions++
                        error("Status must never decrypt a child name")
                    })
                }, durability = jvmOfflineDurability(root))
            val session = controlled.openWithKeyMaterial(account.id, location, material)!!
            try {
                val page =
                    listOf(
                        cached[0],
                        cached[129],
                        cached[3].copy(strongETag = "\"changed\""),
                        cached[4].copy(id = "replaced"),
                        cached[5].copy(size = 999),
                        fileEntry("missing", 49),
                    )
                assertEquals(listOf(cached[0], cached[129]), session.matchingFiles(page))
                assertEquals(0, nameDecryptions)
                assertThrows(IllegalArgumentException::class.java) {
                    runBlocking { session.matchingFiles(List(257) { cached[0] }) }
                }
                store.pinDirectory(identity, location, "Secret.vault/new-child", material)
                assertThrows(OpenCloudException::class.java) { runBlocking { session.matchingFiles(page) } }
                assertEquals(0, nameDecryptions)
            } finally {
                session.close()
                encrypted.fill(0)
            }
        }

    @Test fun offlineDestinationExclusionPrecedesCountAndPreservesSimilarPrefixes() =
        runBlocking {
            val names = listOf("source", "source-extra") + (0 until 130).map { "other-$it" }
            names.forEach { store.pinDirectory(identity, location, "Secret.vault/$it", material) }
            store.pinDirectory(identity, location, "Secret.vault/source/child", material)
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            try {
                session.openDirectory(excludedPath = "source").use { snapshot ->
                    assertEquals(131L, snapshot.totalCount)
                    val first = snapshot.page(0, 128)
                    val second = snapshot.page(first.size.toLong(), 128)
                    assertEquals(3, second.size)
                    assertTrue((first + second).any { it.path == "source-extra" })
                    assertTrue((first + second).none { it.path == "source" })
                }
                session.openDirectory("source", excludedPath = "source").use { snapshot ->
                    assertEquals(0L, snapshot.totalCount)
                }
                listOf("", "../source", "/source").forEach { excluded ->
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { session.openDirectory(excludedPath = excluded) }
                    }
                }
            } finally {
                session.close()
            }
        }

    @Test fun individualMetadataRecordBoundPreservesPreviousAuthenticatedFileAndMetadata() =
        runBlocking {
            val original = fakeCiphertext("previous accepted content".toByteArray())
            val replacement = fakeCiphertext("replacement content".toByteArray())
            val entry = fileEntry("opaque-original", original.size.toLong())
            store.pinFile(identity, location, entry, material) { it.write(original) }
            val manifest = root.walkTopDown().single { it.name == "manifest.enc" }
            val previousManifest = manifest.readBytes()
            val previousFiles =
                root
                    .walkTopDown()
                    .filter(File::isFile)
                    .map { it.relativeTo(root).path }
                    .toSet()
            try {
                // Aggregate metadata is paged; one malformed opaque field still exceeds the bounded record decoder.
                val oversized = entry.copy(id = "x".repeat(16 * 1024 * 1024), size = replacement.size.toLong())
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { store.pinFile(identity, location, oversized, material) { it.write(replacement) } }
                    }
                assertEquals(OpenCloudError.EncryptedOfflineIndexFull, failure.error)
                assertArrayEquals(previousManifest, manifest.readBytes())
                val actualFiles =
                    root
                        .walkTopDown()
                        .filter(File::isFile)
                        .map { it.relativeTo(root).path }
                        .toSet()
                assertEquals(previousFiles, actualFiles)
                val session = store.openWithKeyMaterial(account.id, location, material)!!
                try {
                    val saved = session.list().single()
                    assertEquals(entry.id, saved.id)
                    val output = ByteArrayOutputStream()
                    session.download(saved, output)
                    assertArrayEquals("previous accepted content".toByteArray(), output.toByteArray())
                } finally {
                    session.close()
                }
            } finally {
                previousManifest.fill(0)
                original.fill(0)
                replacement.fill(0)
            }
        }

    private fun fileEntry(
        name: String,
        size: Long,
    ) = VaultFolder(
        id = name,
        name = name,
        rawName = name,
        path = name,
        encryptedPath = "Secret.vault/$name",
        isFolder = false,
        size = size,
        strongETag = "\"tag\"",
    )

    private fun fakeCiphertext(plain: ByteArray) = ByteArray(32) { 7 } + plain + ByteArray(16) { 9 }
}
