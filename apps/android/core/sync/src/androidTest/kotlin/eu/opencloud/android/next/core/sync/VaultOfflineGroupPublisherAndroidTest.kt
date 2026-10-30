package eu.opencloud.android.next.core.sync

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.FileBrowserStore
import eu.opencloud.android.next.core.database.TransferEntity
import eu.opencloud.android.next.core.database.VaultGroupCheckpoint
import eu.opencloud.android.next.core.database.VaultGroupMemberAdmission
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
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.util.UUID

/** Real Room, Android SQLite, directory fsync and rclone authentication; no transport or power-loss claim. */
@RunWith(AndroidJUnit4::class)
class VaultOfflineGroupPublisherAndroidTest {
    @Test fun actualPlatformRejectsLateValidPayloadReplacementThenPublishesOneCompleteCapturedSubtree() =
        runBlocking {
            val app = InstrumentationRegistry.getInstrumentation().targetContext
            val root = File(app.noBackupFilesDir, "group-publisher-native-${UUID.randomUUID()}")
            assertTrue(root.mkdir())
            val database = Room.inMemoryDatabaseBuilder(app, FileBrowserDatabase::class.java).build()
            val material = ByteArray(80) { it.toByte() }
            val account =
                AccountEntity(UUID.randomUUID().toString(), "https://example.test/", "u", "User", "BASIC", false)
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
            val durability = OfflineDurability(app.noBackupFilesDir)
            val databaseStore = FileBrowserStore(database)
            val groups = databaseStore.vaultOfflineGroups()
            var publications = 0
            val offline =
                VaultOfflineStore(
                    File(root, "offline"),
                    { database.accountDao().findById(it) },
                    { { true } },
                    EndpointPolicy(true),
                    { RcloneVaultCipher.fromKeyMaterial(it).offlineEngine() },
                    afterPublication = { publications++ },
                    durability = durability,
                    groupPublications = { groups },
                )
            val plans = VaultOfflineGroupPlanStore(File(root, "plans"), durability)

            fun raw(value: String) = RcloneVaultCipher.fromKeyMaterial(material).use { it.encryptName(value) }

            fun encrypted(value: String): ByteArray =
                ByteArrayOutputStream().use { output ->
                    RcloneVaultCipher.fromKeyMaterial(material).use {
                        it.encryptContent(
                            value.byteInputStream(),
                            output,
                            1024 * 1024,
                        )
                    }
                    output.toByteArray()
                }

            fun source(
                path: String,
                folder: Boolean,
                size: Long,
            ) = VaultDavEntry(
                UUID.randomUUID().toString(),
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
            try {
                database.accountDao().upsert(account)
                val old = encrypted("old-outside")
                val outsideRaw = raw("outside")
                val outside =
                    VaultFolder(
                        "outside",
                        "outside",
                        outsideRaw,
                        "outside",
                        "${location.vaultPath}/$outsideRaw",
                        false,
                        old.size.toLong(),
                        "\"old\"",
                    )
                offline.pinFile(identity, location, outside, material) { it.write(old) }
                val baselinePublications = publications
                val manifest = File(root, "offline").walkTopDown().single { it.name == "manifest.enc" }
                val previous = manifest.readBytes()
                val directory = manifest.parentFile!!
                val owner = requireNotNull(groups.captureOwner(account.id))
                val selected = "${location.vaultPath}/${raw("selected")}"
                val context =
                    VaultOfflineGroupContext(
                        UUID.randomUUID().toString(),
                        owner,
                        identity,
                        location.copy(title = ""),
                        selected,
                        "2".repeat(64),
                        sha(previous),
                    )
                var preparation = requireNotNull(groups.beginPreparation(owner, context.descriptor()))
                val payloadBytes = listOf(encrypted("first-file"), encrypted("last--file"))
                val members = mutableListOf<VaultOfflineGroupMember>()
                val seal =
                    plans.begin(context).use { capture ->
                        members += capture.appendDirectory(source(selected, true, 0))
                        members += capture.appendDirectory(source("$selected/${raw("empty")}", true, 0))
                        members +=
                            capture.appendFile(
                                source("$selected/${raw("first")}", false, payloadBytes[0].size.toLong()),
                            )
                        members +=
                            capture.appendFile(source("$selected/${raw("last")}", false, payloadBytes[1].size.toLong()))
                        capture.seal(material).also { assertTrue(capture.finishPrepared { true }) }
                    }
                preparation =
                    requireNotNull(
                        groups.appendMembers(
                            preparation,
                            0,
                            members.map {
                                VaultGroupMemberAdmission(
                                    it.sequence,
                                    it.id,
                                    it.descriptorDigest,
                                    it.kind.name,
                                    it.payloadId,
                                )
                            },
                            preparation.group.stagingChainDigest,
                            "3".repeat(64),
                        ),
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
                val queued = requireNotNull(groups.sealAndEnqueue(preparation, seal, parent) { true })
                var attempt = requireNotNull(groups.claim(queued, UUID.randomUUID().toString(), 2))
                val payloads = mutableListOf<File>()
                plans.open(owner, context.groupId).use { opaque ->
                    groups.memberPage(attempt.lease).filter { it.kind == "FILE" }.forEachIndexed { index, row ->
                        val member = members.single { it.id == row.memberId }
                        val payload = plans.payloads(owner, context.groupId).partial(opaque.fileJob(member))
                        payload.writeBytes(payloadBytes[index])
                        payloads += payload
                        attempt =
                            requireNotNull(
                                groups.checkpoint(
                                    attempt,
                                    row,
                                    VaultGroupCheckpoint(
                                        "DOWNLOADED",
                                        payloadBytes[index].size.toLong(),
                                        sha(payloadBytes[index]),
                                    ),
                                ),
                            ).attempt
                    }
                }
                val awaiting = requireNotNull(groups.awaitUnlock(attempt, 3))
                val replacement = encrypted("other-file")
                assertEquals(payloads.last().length(), replacement.size.toLong())
                payloads.last().writeBytes(replacement)
                plans.open(owner, context.groupId).use { opaque ->
                    opaque.verify(material, context).use { verified ->
                        val failure =
                            assertThrows(OpenCloudException::class.java) {
                                runBlocking {
                                    offline.publishPreparedGroup(
                                        verified,
                                        location,
                                        material,
                                        awaiting,
                                        groups,
                                        { true },
                                    )
                                }
                            }
                        assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
                    }
                }
                assertArrayEquals(previous, manifest.readBytes())
                assertEquals(baselinePublications, publications)
                assertEquals(null, VaultOfflinePublicationJournal.read(directory))
                payloads.last().writeBytes(payloadBytes.last())
                plans.open(owner, context.groupId).use { opaque ->
                    opaque.verify(material, context).use { verified ->
                        offline.publishPreparedGroup(verified, location, material, awaiting, groups, { true })
                    }
                }
                assertEquals(baselinePublications + 1, publications)
                assertFalse(previous.contentEquals(manifest.readBytes()))
                assertEquals("SUCCEEDED", groups.find(context.groupId)!!.group.state)
                assertEquals("SUCCEEDED", databaseStore.transfer(context.groupId)!!.state)
                assertEquals(null, VaultOfflinePublicationJournal.read(directory))
                offline.openWithKeyMaterial(account.id, location, material)!!.use { session ->
                    assertEquals(setOf("outside", "selected"), session.list().map(VaultFolder::name).toSet())
                    val children = session.list("selected")
                    assertEquals(setOf("first", "last", "empty"), children.map(VaultFolder::name).toSet())
                    val output = ByteArrayOutputStream()
                    session.download(children.single { it.name == "last" }, output)
                    assertEquals("last--file", output.toString(Charsets.UTF_8.name()))
                    assertTrue(session.list("selected/empty").isEmpty())
                }
            } finally {
                database.close()
                material.fill(0)
                root.deleteRecursively()
            }
        }

    private fun sha(bytes: ByteArray): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { "%02x".format(it) }
}
