package eu.opencloud.android.next.core.sync

import androidx.room.Room
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.VaultGroupCheckpoint
import eu.opencloud.android.next.core.database.VaultGroupLease
import eu.opencloud.android.next.core.database.VaultGroupMemberAdmission
import eu.opencloud.android.next.core.database.VaultGroupPublication
import eu.opencloud.android.next.core.database.VaultGroupPublicationDecision
import eu.opencloud.android.next.core.database.vaultOfflineGroups
import eu.opencloud.android.next.core.network.EndpointPolicy
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.runBlocking
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupPublisherTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun genuineCapturedSubtreePublishesOncePreservesOutsideAndEmptyDirectoryAndAuthenticatesAllFiles() =
        fixture { f ->
            f.prepare()
            var publications = 0
            f.after = { publications++ }
            f.publish()
            assertEquals(1, publications)
            assertFalse(f.base.contentEquals(f.manifest.readBytes()))
            assertEquals(
                "SUCCEEDED",
                f.groups
                    .find(f.context.groupId)!!
                    .group.state,
            )
            assertEquals("SUCCEEDED", f.databaseStore.transfer(f.context.groupId)!!.state)
            assertEquals(null, VaultOfflinePublicationJournal.read(f.directory))
            f.offline.openWithKeyMaterial(f.account.id, f.location, f.material)!!.use { session ->
                val root = session.list()
                assertEquals(setOf("outside", "selected"), root.map(VaultFolder::name).toSet())
                assertEquals("outside-old", f.read(session, root.single { it.name == "outside" }))
                val children = session.list("selected")
                assertEquals(setOf("first", "last", "empty"), children.map(VaultFolder::name).toSet())
                assertEquals("fresh-one", f.read(session, children.single { it.name == "first" }))
                assertEquals("fresh-two", f.read(session, children.single { it.name == "last" }))
                assertTrue(session.list("selected/empty").isEmpty())
            }
            assertFalse(f.oldBlob.exists())
            assertEquals(3, File(f.directory, "blobs").listFiles().orEmpty().size)
        }

    @Test fun rootDirectoryMemberIsVerifiedButNeverStoredAsAnOfflineChild() =
        fixture { f ->
            f.prepare(entireVault = true)
            f.publish()
            readOfflineManifest(f.manifest, f.identity, f.location, f.material, f.durability).use { index ->
                assertEquals(null, index.find(f.location.vaultPath))
                var files = 0
                index.visit { if (!it.isFolder) files++ }
                assertEquals(2, files)
            }
        }

    @Test fun missingOrCorruptLastChildLeavesPreviousRootAndEveryPreviousBlobReadable() {
        for (missing in listOf(true, false)) {
            fixture { f ->
                f.prepare()
                if (missing) {
                    assertTrue(f.payloads.last().delete())
                } else {
                    val bytes = f.payloads.last().readBytes()
                    bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
                    f.payloads.last().writeBytes(bytes)
                }
                assertThrows(OpenCloudException::class.java) { runBlocking { f.publish() } }
                f.assertOldSnapshot()
                assertEquals(
                    null,
                    f.groups
                        .find(f.context.groupId)!!
                        .group.pendingPublicationId,
                )
            }
        }
    }

    @Test fun validSameKeyLastPayloadReplacementCannotPassTheDownloadedCheckpointCommitment() =
        fixture { f ->
            f.prepare()
            val replacement = f.encrypt("other-two")
            assertEquals(f.payloads.last().length(), replacement.size.toLong())
            f.payloads.last().writeBytes(replacement)
            val failure = assertThrows(OpenCloudException::class.java) { runBlocking { f.publish() } }
            assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
            f.assertOldSnapshot()
        }

    @Test fun lateCheckpointDigestOrSealedMemberBindingMismatchCannotPublishACompleteCandidate() {
        for (column in listOf("ciphertextDigest", "descriptorDigest")) {
            fixture { f ->
                f.prepare()
                val sequence = f.members.last { it.kind == VaultOfflineGroupMemberKind.FILE }.sequence
                f.database.openHelper.writableDatabase.execSQL(
                    "UPDATE vault_offline_group_members SET $column=? WHERE groupId=? AND sequence=?",
                    arrayOf("f".repeat(64), f.context.groupId, sequence),
                )
                val failure = assertThrows(OpenCloudException::class.java) { runBlocking { f.publish() } }
                assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
                f.assertOldSnapshot()
            }
        }
    }

    @Test fun independentCommittedRootChangeAndDisabledCurrentGrantRefuseBeforePublication() {
        for (disabled in listOf(false, true)) {
            fixture { f ->
                f.prepare()
                val expected =
                    if (disabled) {
                        f.base
                    } else {
                        f.offline.pinDirectory(
                            f.identity,
                            f.location,
                            "${f.location.vaultPath}/${f.raw("later")}",
                            f.material,
                        )
                        f.manifest.readBytes()
                    }
                var publications = 0
                f.after = { publications++ }
                val failure =
                    assertThrows(OpenCloudException::class.java) {
                        runBlocking { f.publish(if (disabled) f.location.copy(isDisabled = true) else f.location) }
                    }
                if (!disabled) assertEquals(OpenCloudError.OfflineSnapshotChanged, failure.error)
                assertArrayEquals(expected, f.manifest.readBytes())
                assertEquals(0, publications)
                assertEquals(
                    null,
                    f.groups
                        .find(f.context.groupId)!!
                        .group.pendingPublicationId,
                )
            }
        }
    }

    @Test fun cancellationAfterRootSwitchAndHistoryClearRestoresBaseUsingIndependentRejectedReceipt() =
        fixture { f ->
            f.prepare()
            var exact: VaultGroupPublication? = null
            f.after = {
                exact = VaultOfflinePublicationJournal.read(f.directory)!!.groupPublication
                runBlocking {
                    val reserved = requireNotNull(f.groups.find(f.context.groupId))
                    assertNotNull(f.groups.cancel(reserved, 50))
                    f.databaseStore.clearTransferHistory(f.account.id)
                }
            }
            assertThrows(OpenCloudException::class.java) { runBlocking { f.publish() } }
            f.assertOldSnapshot()
            assertEquals(null, f.databaseStore.transfer(f.context.groupId))
            assertEquals(VaultGroupPublicationDecision.REJECTED, f.groups.publicationDecision(requireNotNull(exact)))
            assertFalse(f.groups.hasUnresolved(f.context.owner, f.context.groupId))
        }

    @Test fun lockRevocationAtFinalCheckRetainsBaseWithoutDecryptingForCleanup() =
        fixture { f ->
            f.prepare()
            var permitted = true
            f.after = { permitted = false }
            assertThrows(OpenCloudException::class.java) { runBlocking { f.publish(permit = { permitted }) } }
            assertArrayEquals(f.base, f.manifest.readBytes())
            assertTrue(f.oldBlob.isFile)
            assertEquals(null, VaultOfflinePublicationJournal.read(f.directory))
            // A later fresh authorization owns authenticated orphan cleanup.
            f.assertOldSnapshot()
        }

    @Test fun accountRemovalAndIdenticalReaddNeverAuthorizesOldReceiptOrDeletesRetainedBase() =
        fixture { f ->
            f.prepare()
            val priorIndex = File(f.directory, "indexes/${VaultOfflineIndex.generation(f.base)}.db")
            var exact: VaultGroupPublication? = null
            f.after = {
                exact = VaultOfflinePublicationJournal.read(f.directory)!!.groupPublication
                runBlocking {
                    f.databaseStore.removeAccount(f.account.id)
                    f.database.accountDao().upsert(f.account)
                    val replacement = requireNotNull(f.groups.captureOwner(f.account.id))
                    assertNotEquals(f.context.owner.incarnation, replacement.incarnation)
                }
            }
            assertThrows(OpenCloudException::class.java) { runBlocking { f.publish() } }
            assertTrue(priorIndex.isFile)
            assertTrue(f.oldBlob.isFile)
            assertNotNull(VaultOfflinePublicationJournal.read(f.directory))
            assertEquals(VaultGroupPublicationDecision.REVOKED, f.groups.publicationDecision(requireNotNull(exact)))
            val current = f.manifest.readBytes()
            assertThrows(OpenCloudException::class.java) {
                runBlocking { f.offline.recoverPendingPublications(f.account.id) }
            }
            assertArrayEquals(current, f.manifest.readBytes())
            assertTrue(priorIndex.isFile)
            assertTrue(f.oldBlob.isFile)
        }

    @Test fun missingReceiptAuthorityRetainsBothGenerationsAndJournalWithoutGuessingCompletion() =
        fixture { f ->
            f.prepare()
            val oldIndex = File(f.directory, "indexes/${VaultOfflineIndex.generation(f.base)}.db")
            f.after = {
                val exact = requireNotNull(VaultOfflinePublicationJournal.read(f.directory)!!.groupPublication)
                f.database.openHelper.writableDatabase.execSQL(
                    "DELETE FROM vault_offline_group_publications WHERE publicationId=?",
                    arrayOf(exact.publicationId),
                )
                error("synthetic missing authority after root switch")
            }
            assertThrows(OpenCloudException::class.java) { runBlocking { f.publish() } }
            val pending = requireNotNull(VaultOfflinePublicationJournal.read(f.directory))
            assertEquals(
                VaultGroupPublicationDecision.UNKNOWN,
                f.groups.publicationDecision(requireNotNull(pending.groupPublication)),
            )
            assertTrue(oldIndex.isFile)
            assertTrue(File(f.directory, "indexes/${VaultOfflineIndex.generation(f.manifest.readBytes())}.db").isFile)
            assertTrue(f.oldBlob.isFile)
            assertFalse(f.base.contentEquals(f.manifest.readBytes()))
        }

    @Test fun preparedReceiptBeforeFilesystemJournalCanBeResolvedOnlyAgainstExactBase() =
        fixture { f ->
            f.prepare()
            val exact =
                VaultGroupPublication(
                    UUID.randomUUID().toString(),
                    f.context.groupId,
                    f.context.owner,
                    f.context.identityDigest,
                    f.context.descriptorDigest,
                    f.sealDigest,
                    f.members.size.toLong(),
                    f.context.baseOfflineRootDigest,
                    "a".repeat(64),
                )
            assertNotNull(f.groups.reservePublication(f.lease, exact) { true })
            assertEquals(
                VaultGroupPublicationDecision.REJECTED,
                f.offline.resolveUnjournaledGroupPublication(f.identity, f.location, exact, f.groups),
            )
            assertFalse(f.groups.hasUnresolved(f.context.owner, f.context.groupId))
            assertArrayEquals(f.base, f.manifest.readBytes())
        }

    private fun fixture(block: suspend (Fixture) -> Unit) =
        runBlocking {
            val fixture = Fixture(temporary.newFolder())
            try {
                fixture.initialize()
                block(fixture)
            } finally {
                fixture.close()
            }
        }

    private class Fixture(
        val root: File,
    ) : AutoCloseable {
        val material = ByteArray(80) { it.toByte() }
        val database =
            Room
                .inMemoryDatabaseBuilder(
                    RuntimeEnvironment.getApplication(),
                    FileBrowserDatabase::class.java,
                ).build()
        val databaseStore = FileBrowserStore(database)
        val groups = databaseStore.vaultOfflineGroups()
        val account = AccountEntity(UUID.randomUUID().toString(), "https://example.test/", "u", "User", "BASIC", false)
        val identity = VaultIdentity(account.id, account.serverUrl, "drive", "vault")
        val location =
            VaultLocation(
                account.id,
                "Secret.vault",
                VaultLocationKind.FOLDER_VAULT,
                "drive",
                "vault",
                "root",
                account.serverUrl,
                "https://example.test/dav/",
                "Secret.vault",
                true,
            )
        val durability = jvmOfflineDurability(root)
        val planStore = VaultOfflineGroupPlanStore(File(root, "plans"), durability)
        var before: () -> Unit = {}
        var after: () -> Unit = {}
        val offline =
            VaultOfflineStore(
                File(root, "offline"),
                { database.accountDao().findById(it) },
                { { true } },
                EndpointPolicy(true),
                { jvmRcloneVaultCipher(it).offlineEngine() },
                beforePublication = { before() },
                afterPublication = { after() },
                durability = durability,
                groupPublications = { groups },
            )
        lateinit var context: VaultOfflineGroupContext
        lateinit var lease: VaultGroupLease
        lateinit var base: ByteArray
        lateinit var oldBlob: File
        lateinit var sealDigest: String
        val members = mutableListOf<VaultOfflineGroupMember>()
        val payloads = mutableListOf<File>()
        val manifest: File get() = File(root, "offline").walkTopDown().single { it.name == "manifest.enc" }
        val directory: File get() = manifest.parentFile!!

        suspend fun initialize() {
            database.accountDao().upsert(account)
            pin("selected/old", "selected-old")
            pin("outside", "outside-old")
            base = manifest.readBytes()
            oldBlob =
                readOfflineManifest(manifest, identity, location, material, durability).use {
                    File(
                        directory,
                        "blobs/${it.find("${location.vaultPath}/${raw("selected")}/${raw("old")}")!!.blobId}",
                    )
                }
        }

        suspend fun prepare(entireVault: Boolean = false) {
            val owner = requireNotNull(groups.captureOwner(account.id))
            val selected = if (entireVault) location.vaultPath else "${location.vaultPath}/${raw("selected")}"
            context =
                VaultOfflineGroupContext(
                    UUID.randomUUID().toString(),
                    owner,
                    identity,
                    location.copy(title = ""),
                    selected,
                    "2".repeat(64),
                    offlineMetadataDigest(base),
                )
            var prepared = requireNotNull(groups.beginPreparation(owner, context.descriptor()))
            val data = listOf("fresh-one", "fresh-two")
            val seal =
                planStore.begin(context).use { plan ->
                    val selectedId = if (entireVault) identity.remoteVaultId else "selected"
                    members += plan.appendDirectory(source(selected, selectedId, true, 0))
                    members += plan.appendDirectory(source("$selected/${raw("empty")}", "empty", true, 0))
                    data.forEachIndexed { index, text ->
                        val name = if (index == 0) "first" else "last"
                        members +=
                            plan.appendFile(source("$selected/${raw(name)}", name, false, encrypt(text).size.toLong()))
                    }
                    plan.seal(material).also { assertTrue(plan.finishPrepared { true }) }
                }
            sealDigest = seal.digest
            val admissions =
                members.map {
                    VaultGroupMemberAdmission(it.sequence, it.id, it.descriptorDigest, it.kind.name, it.payloadId)
                }
            prepared =
                requireNotNull(
                    groups.appendMembers(prepared, 0, admissions, prepared.group.stagingChainDigest, "3".repeat(64)),
                )
            val parent =
                TransferEntity(
                    id = context.groupId,
                    accountId = account.id,
                    spaceId = identity.driveId,
                    resourceId = null,
                    direction = "DOWNLOAD",
                    sourceUri = "vault-offline-group:${identity.remoteVaultId}",
                    destinationPath = selected,
                    displayName = "Encrypted offline folder",
                    mimeType = null,
                    bytesTotal = seal.ciphertextBytes,
                    offlinePin = true,
                    locationKind = "VAULT_GROUP",
                    createdAtEpochMillis = 1,
                    updatedAtEpochMillis = 1,
                )
            val queued = requireNotNull(groups.sealAndEnqueue(prepared, seal, parent) { true })
            var attempt = requireNotNull(groups.claim(queued, UUID.randomUUID().toString(), 2))
            planStore.open(owner, context.groupId).use { opaque ->
                val rows = groups.memberPage(attempt.lease).filter { it.kind == "FILE" }
                rows.forEachIndexed { index, row ->
                    val member = members.single { it.id == row.memberId }
                    val payload = planStore.payloads(owner, context.groupId).partial(opaque.fileJob(member))
                    val bytes = encrypt(data[index])
                    payload.writeBytes(bytes)
                    payloads += payload
                    attempt =
                        requireNotNull(
                            groups.checkpoint(
                                attempt,
                                row,
                                VaultGroupCheckpoint("DOWNLOADED", bytes.size.toLong(), digest(bytes)),
                            ),
                        ).attempt
                }
            }
            lease = requireNotNull(groups.awaitUnlock(attempt, 3))
        }

        suspend fun publish(
            current: VaultLocation = location,
            permit: () -> Boolean = { true },
        ) {
            planStore.open(context.owner, context.groupId).use { opaque ->
                opaque.verify(material, context).use { verified ->
                    offline.publishPreparedGroup(verified, current, material, lease, groups, permit)
                }
            }
        }

        suspend fun assertOldSnapshot() {
            assertArrayEquals(base, manifest.readBytes())
            assertTrue(oldBlob.isFile)
            assertEquals(null, VaultOfflinePublicationJournal.read(directory))
            offline.openWithKeyMaterial(account.id, location, material)!!.use { session ->
                assertEquals("selected-old", read(session, session.list("selected").single()))
                assertEquals("outside-old", read(session, session.list().single { it.name == "outside" }))
            }
        }

        suspend fun pin(
            path: String,
            text: String,
        ) {
            val encrypted = jvmRcloneVaultCipher(material).use { it.encryptPath(path) }
            val bytes = encrypt(text)
            val entry =
                VaultFolder(
                    path,
                    path.substringAfterLast('/'),
                    encrypted.substringAfterLast('/'),
                    path,
                    "${location.vaultPath}/$encrypted",
                    false,
                    bytes.size.toLong(),
                    "\"old\"",
                )
            offline.pinFile(identity, location, entry, material) { it.write(bytes) }
        }

        fun raw(value: String): String = jvmRcloneVaultCipher(material).use { it.encryptName(value) }

        fun encrypt(text: String): ByteArray =
            ByteArrayOutputStream().use { output ->
                jvmRcloneVaultCipher(material).use {
                    it.encryptContent(
                        text.byteInputStream(),
                        output,
                        1024 * 1024,
                    )
                }
                output.toByteArray()
            }

        fun source(
            path: String,
            id: String,
            folder: Boolean,
            size: Long,
        ) = VaultDavEntry(
            id,
            path,
            path.substringAfterLast('/'),
            folder,
            size,
            "\"captured\"",
            location.rootWebDavUrl
                .toHttpUrl()
                .newBuilder()
                .addPathSegments(path)
                .build()
                .toString(),
        )

        suspend fun read(
            session: VaultOfflineSession,
            entry: VaultFolder,
        ): String =
            ByteArrayOutputStream().use {
                session.download(entry, it)
                it.toString(Charsets.UTF_8.name())
            }

        private fun digest(bytes: ByteArray) =
            MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") {
                "%02x".format(it)
            }

        override fun close() {
            database.close()
            material.fill(0)
        }
    }
}
