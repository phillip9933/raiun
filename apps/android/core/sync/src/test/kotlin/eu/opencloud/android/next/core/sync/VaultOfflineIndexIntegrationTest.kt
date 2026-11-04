package eu.opencloud.android.next.core.sync

import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

@RunWith(RobolectricTestRunner::class)
class VaultOfflineIndexIntegrationTest {
    @get:Rule val temporary = TemporaryFolder()

    private val material = ByteArray(80) { it.toByte() }
    private val server = "https://example.test/"
    private val account = AccountEntity("independent-${UUID.randomUUID()}", server, "user", "User", "BASIC", false)
    private val identity = VaultIdentity(account.id, server, "drive", "vault-id")
    private val location =
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

    @After fun wipeMaterial() {
        material.fill(0)
    }

    @Test fun cancellationBeforeOpenDeliveryClosesCipherAndDoesNotStrandGenerationReader() =
        runBlocking {
            val root = temporary.newFolder()
            val cancellationTarget = AtomicReference<Job?>()
            val closes = AtomicInteger()
            val store =
                store(root, factory = {
                    val cipher =
                        object : VaultCipherEngine by VaultOfflineTestCipher() {
                            override fun close() {
                                closes.incrementAndGet()
                            }
                        }
                    cancellationTarget.get()?.cancel()
                    cipher
                })
            pin(store, "old", "\"v1\"")
            closes.set(0)
            val manifestFile = manifest(root)
            val previousRoot = manifestFile.readBytes()
            val previousIndex = indexFile(manifestFile.parentFile, previousRoot)
            var delivered = false
            val opening =
                launch(start = CoroutineStart.LAZY) {
                    store.openWithKeyMaterial(account.id, location, material)?.use { delivered = true }
                }
            cancellationTarget.set(opening)
            opening.start()
            opening.join()
            cancellationTarget.set(null)
            assertTrue(opening.isCancelled)
            assertFalse(delivered)
            assertEquals(1, closes.get())
            assertArrayEquals(previousRoot, manifestFile.readBytes())

            val nextRoot =
                VaultOfflineIndex.prepare(
                    manifestFile.parentFile,
                    identity,
                    location,
                    material,
                    LegacyOfflineManifest(emptyMap()),
                    durability = jvmOfflineDurability(root),
                )
            manifestFile.writeBytes(nextRoot)
            VaultOfflineIndex.cleanup(manifestFile.parentFile, listOf(nextRoot))
            assertFalse(previousIndex.exists())
        }

    @Test fun refreshDuringDownloadCannotSlideTheCapturedRootFenceAndRetainsOldReaderContent() =
        runBlocking {
            val root = temporary.newFolder()
            val store = store(root)
            pin(store, "old", "\"v1\"")
            val manifestFile = manifest(root)
            val directory = manifestFile.parentFile
            val oldIndex = indexFile(directory, manifestFile.readBytes())
            val oldBlob = File(directory, "blobs").listFiles().orEmpty().single { !it.name.startsWith("staging-") }
            store.openWithKeyMaterial(account.id, location, material)!!.use { session ->
                val issued = session.list().single()
                val written = ByteArrayOutputStream()
                var switched = false
                val sink =
                    object : OutputStream() {
                        override fun write(value: Int) {
                            write(byteArrayOf(value.toByte()))
                        }

                        override fun write(
                            bytes: ByteArray,
                            offset: Int,
                            length: Int,
                        ) {
                            written.write(bytes, offset, length)
                            if (!switched) {
                                switched = true
                                runBlocking {
                                    pin(store, "new", "\"v2\"")
                                    session.openDirectory().use { assertEquals(1L, it.totalCount) }
                                    store.openWithKeyMaterial(account.id, location, material)!!.close()
                                }
                                assertTrue(oldIndex.isFile)
                                assertTrue(oldBlob.isFile)
                            }
                        }
                    }
                assertThrows(OpenCloudException::class.java) { runBlocking { session.download(issued, sink) } }
                assertTrue(switched)
                assertEquals("old", written.toString(Charsets.UTF_8.name()))
                val current = session.list().single()
                assertEquals("\"v2\"", current.strongETag)
                val fresh = ByteArrayOutputStream()
                session.download(current, fresh)
                assertEquals("new", fresh.toString(Charsets.UTF_8.name()))
            }
            store.openWithKeyMaterial(account.id, location, material)!!.close()
            assertFalse(oldIndex.exists())
            assertFalse(oldBlob.exists())
        }

    @Test fun revokedDirectoryPublicationLeavesPreviousRootAndCiphertextByteIdentical() =
        runBlocking {
            val root = temporary.newFolder()
            var permitted = true
            var revokeBeforePublication = false
            val store =
                store(
                    root,
                    permit = { permitted },
                    beforePublication = { if (revokeBeforePublication) permitted = false },
                )
            pin(store, "old", "\"v1\"")
            val manifestFile = manifest(root)
            val previousRoot = manifestFile.readBytes()
            val previousIndex = indexFile(manifestFile.parentFile, previousRoot).readBytes()
            val blob = File(manifestFile.parentFile, "blobs").listFiles().orEmpty().single()
            val previousBlob = blob.readBytes()
            revokeBeforePublication = true
            assertThrows(OpenCloudException::class.java) {
                runBlocking { store.pinDirectory(identity, location, "Secret.vault/new-directory", material) }
            }
            assertArrayEquals(previousRoot, manifestFile.readBytes())
            assertArrayEquals(previousIndex, indexFile(manifestFile.parentFile, previousRoot).readBytes())
            assertArrayEquals(previousBlob, blob.readBytes())
            permitted = true
            store.openWithKeyMaterial(account.id, location, material)!!.use { session ->
                assertEquals(listOf("payload"), session.list().map(VaultFolder::name))
            }
        }

    private fun store(
        root: File,
        permit: () -> Boolean = { true },
        factory: (ByteArray) -> VaultCipherEngine = { VaultOfflineTestCipher() },
        beforePublication: () -> Unit = {},
    ): VaultOfflineStore =
        VaultOfflineStore(
            root,
            { account },
            { permit },
            EndpointPolicy(true),
            factory,
            beforePublication = beforePublication,
            durability = jvmOfflineDurability(root),
        )

    private suspend fun pin(
        store: VaultOfflineStore,
        content: String,
        etag: String,
    ) {
        val encrypted = ByteArray(32) { 7 } + content.toByteArray() + ByteArray(16) { 9 }
        val entry =
            VaultFolder(
                "payload",
                "payload",
                "payload",
                "payload",
                "Secret.vault/payload",
                false,
                encrypted.size.toLong(),
                etag,
            )
        store.pinFile(identity, location, entry, material) { it.write(encrypted) }
    }

    private fun manifest(root: File): File = root.walkTopDown().single { it.name == "manifest.enc" }

    private fun indexFile(
        directory: File,
        root: ByteArray,
    ): File = File(directory, "indexes/${requireNotNull(VaultOfflineIndex.generation(root))}.db")
}
