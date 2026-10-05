package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
class VaultOfflineStoreTest {
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
        store = VaultOfflineStore(root, { currentAccount }, { { true } }, EndpointPolicy(true), { FakeCipher() })
    }

    @After fun tearDown() {
        root.deleteRecursively()
        material.fill(0)
    }

    @Test fun pinnedCiphertextOpensReadOnlyAndKeepsChildNamesOutOfCatalog() =
        runBlocking {
            val plain = "private payload".toByteArray()
            val encrypted = fakeCiphertext(plain)
            val entry = fileEntry("enc_private", encrypted.size.toLong())
            store.pinFile(identity, location, entry, material) { it.write(encrypted) }
            assertTrue(store.hasSnapshot(identity))
            assertEquals(listOf("Secret.vault"), store.locations(account.id).map(VaultLocation::title))
            val catalog = root.walkTopDown().first { it.name == "root.json" }.readText()
            assertFalse(catalog.contains("enc_private"))
            assertFalse(catalog.contains("private payload"))

            val session = store.openWithKeyMaterial(account.id, location, material)!!
            try {
                assertEquals(identity, session.identity)
                val listed = session.list().single()
                assertEquals("enc_private", listed.name)
                val output = ByteArrayOutputStream()
                assertEquals(plain.size.toLong(), session.download(listed, output))
                assertArrayEquals(plain, output.toByteArray())
            } finally {
                session.close()
                plain.fill(0)
                encrypted.fill(0)
            }
        }

    @Test fun hkdfSha256MatchesRfc5869TestCaseOne() {
        val ikm = ByteArray(22) { 0x0b }
        val salt = hex("000102030405060708090a0b0c")
        val info = hex("f0f1f2f3f4f5f6f7f8f9")
        val expected =
            hex(
                "3cb25f25faacd57a90434f64d0362f2a" +
                    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
                    "34007208d5b887185865",
            )
        assertArrayEquals(expected, hkdfSha256(ikm, salt, info, 42))
        ikm.fill(0)
        salt.fill(0)
        info.fill(0)
    }

    @Test fun wrongKeyAndCrossIdentityManifestReplayFailClosed() =
        runBlocking {
            val encrypted = fakeCiphertext(byteArrayOf(1, 2, 3))
            store.pinFile(
                identity,
                location,
                fileEntry("enc_first", encrypted.size.toLong()),
                material,
            ) { it.write(encrypted) }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { store.openWithKeyMaterial(account.id, location, ByteArray(80) { 9 }) }
            }
            val originalManifest = root.walkTopDown().first { it.name == "manifest.enc" }
            val other = location.copy(remoteVaultId = "other-vault")
            val otherIdentity = VaultIdentity(account.id, account.serverUrl, "drive", "other-vault")
            store.pinFile(
                otherIdentity,
                other,
                fileEntry("enc_second", encrypted.size.toLong()),
                material,
            ) { it.write(encrypted) }
            val otherManifest = root.walkTopDown().filter { it.name == "manifest.enc" }.first { it != originalManifest }
            originalManifest.copyTo(otherManifest, overwrite = true)
            assertThrows(OpenCloudException::class.java) {
                runBlocking { store.openWithKeyMaterial(account.id, other, material) }
            }
            Unit
        }

    @Test fun damagedBlobAndAccountRemovalPreventPlaintextAccess() =
        runBlocking {
            val encrypted = fakeCiphertext("secret".toByteArray())
            store.pinFile(
                identity,
                location,
                fileEntry("enc_data", encrypted.size.toLong()),
                material,
            ) { it.write(encrypted) }
            val session = store.openWithKeyMaterial(account.id, location, material)!!
            val listed = session.list().single()
            val blob = root.walkTopDown().first { it.parentFile?.name == "blobs" && !it.name.startsWith("staging-") }
            blob.writeBytes(blob.readBytes().also { it[32] = (it[32].toInt() xor 1).toByte() })
            val output = ByteArrayOutputStream()
            assertThrows(OpenCloudException::class.java) { runBlocking { session.download(listed, output) } }
            assertEquals(0, output.size())
            currentAccount = null
            assertThrows(OpenCloudException::class.java) { runBlocking { session.list() } }
            store.forgetAccount(account.id)
            assertFalse(root.walkTopDown().any { it.name == "manifest.enc" })
            session.close()
        }

    @Test fun partialPinFailureLeavesNoPublishedSnapshotOrStage() =
        runBlocking {
            val encrypted = fakeCiphertext(byteArrayOf(1, 2, 3))
            assertThrows(IOException::class.java) {
                runBlocking {
                    store.pinFile(identity, location, fileEntry("enc_partial", encrypted.size.toLong()), material) {
                        it.write(encrypted, 0, 10)
                        throw IOException("synthetic interruption")
                    }
                }
            }
            assertFalse(store.hasSnapshot(identity))
            assertFalse(root.walkTopDown().any { it.name.startsWith("staging-") })
        }

    @Test fun revokeBlocksOpenAndExistingSessionBeforeWaitingForPin() {
        val encrypted = fakeCiphertext(byteArrayOf(1, 2, 3))
        runBlocking {
            store.pinFile(identity, location, fileEntry("enc_existing", encrypted.size.toLong()), material) {
                it.write(encrypted)
            }
        }
        val session = runBlocking { store.openWithKeyMaterial(account.id, location, material)!! }
        val pinStarted = CountDownLatch(1)
        val releasePin = CountDownLatch(1)
        val workers = Executors.newFixedThreadPool(2)
        try {
            val pin =
                workers.submit<Unit> {
                    runBlocking {
                        store.pinFile(
                            identity,
                            location,
                            fileEntry("enc_refresh", encrypted.size.toLong()),
                            material,
                        ) {
                            pinStarted.countDown()
                            check(releasePin.await(5, TimeUnit.SECONDS))
                            it.write(encrypted)
                        }
                    }
                }
            assertTrue(pinStarted.await(5, TimeUnit.SECONDS))
            val removal = workers.submit<Unit> { runBlocking { store.remove(identity) } }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            while (!VaultOfflineRevocations.identityBlocked(identity) && System.nanoTime() < deadline) {
                Thread.sleep(5)
            }
            assertTrue(VaultOfflineRevocations.identityBlocked(identity))
            assertThrows(OpenCloudException::class.java) { runBlocking { session.list() } }
            assertThrows(OpenCloudException::class.java) {
                runBlocking { store.openWithKeyMaterial(account.id, location, material) }
            }
            releasePin.countDown()
            assertThrows(java.util.concurrent.ExecutionException::class.java) { pin.get(5, TimeUnit.SECONDS) }
            removal.get(5, TimeUnit.SECONDS)
            assertFalse(runBlocking { store.hasSnapshot(identity) })
        } finally {
            releasePin.countDown()
            session.close()
            workers.shutdownNow()
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

    private fun hex(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private class FakeCipher : VaultCipherEngine {
        override fun createIntegrityToken() = "proof"

        override fun verifyIntegrityToken(base64Token: String) = true

        override fun decryptName(encrypted: String) = encrypted

        override fun decryptPath(encrypted: String) = encrypted

        override fun encryptName(plain: String) = plain

        override fun encryptPath(plain: String) = plain

        override fun encryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long = 0L

        override fun decryptContent(
            input: InputStream,
            output: OutputStream,
            maximumPlaintextBytes: Long,
        ): Long {
            val bytes = input.readBytes()
            require(
                bytes.size >= 48 &&
                    bytes.take(32).all { it == 7.toByte() } &&
                    bytes.takeLast(16).all { it == 9.toByte() },
            )
            val plain = bytes.copyOfRange(32, bytes.size - 16)
            require(plain.size.toLong() <= maximumPlaintextBytes)
            output.write(plain)
            val size = plain.size.toLong()
            plain.fill(0)
            bytes.fill(0)
            return size
        }

        override fun exportKeyMaterial() = ByteArray(80)

        override fun close() = Unit
    }
}
