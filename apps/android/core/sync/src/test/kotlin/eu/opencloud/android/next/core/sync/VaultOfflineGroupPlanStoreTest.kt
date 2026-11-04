package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.database.VaultGroupSeal
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.security.VaultIdentity
import kotlinx.coroutines.CancellationException
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.util.UUID

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupPlanStoreTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun aggregateDirectorySizesRemainAuthenticatedWithoutCountingAsFileBytes() =
        fixture { f ->
            val context = f.context
            val root = f.root(context).copy(size = 9_000_000_000L)
            val folder = f.source("${root.relativePath}/${f.raw("folder")}", "folder", true).copy(size = 4096L)
            val file = f.source("${folder.relativePath}/${f.raw("file")}", "file", false)
            val empty = f.source("${root.relativePath}/${f.raw("empty")}", "empty", true)
            f.store.begin(context).use { preparation ->
                preparation.appendDirectory(root)
                preparation.appendDirectory(folder)
                preparation.appendFile(file)
                preparation.appendDirectory(empty)
                val seal = preparation.seal(f.material)
                assertEquals(4L, seal.memberCount)
                assertEquals(1L, seal.fileCount)
                assertEquals(file.size, seal.ciphertextBytes)
                assertTrue(preparation.finishPrepared { true })
            }
            f.store.open(context.owner, context.groupId).use { opaque ->
                opaque.verify(f.material, context).use { verified ->
                    val sources = mutableListOf<VaultDavEntry>()
                    verified.visitVerified { sources.add(it.source) }
                    assertEquals(listOf(root, folder, file, empty), sources)
                }
            }
        }

    @Test fun sealedMembershipPagesBeyond128IncludesDeepAndEmptyDirectoriesAndOriginalJobs() =
        fixture { f ->
            val context = f.context
            val rawParent = f.raw("parent")
            var parent = "${context.selectedEncryptedRoot}/$rawParent"
            val seal =
                f.build(context) { preparation ->
                    preparation.appendDirectory(f.source(parent, "parent", true))
                    repeat(19) { depth ->
                        parent = parent + "/" + f.raw("depth-$depth")
                        preparation.appendDirectory(f.source(parent, "depth-$depth", true))
                    }
                    preparation.appendDirectory(f.source("$parent/${f.raw("empty")}", "empty", true))
                    repeat(
                        257,
                    ) { preparation.appendFile(f.source("$parent/${f.raw(it.toString())}", "file-$it", false)) }
                }
            assertEquals(279L, seal.memberCount)
            assertEquals(257L, seal.fileCount)
            assertEquals(257L * 64, seal.ciphertextBytes)
            f.store.open(context.owner, context.groupId).use { opaque ->
                var after: Long? = null
                var count = 0L
                while (true) {
                    val page = opaque.page(after)
                    if (page.isEmpty()) break
                    assertTrue(page.size in 1..128)
                    page.forEach { assertEquals(count++, it.sequence) }
                    after = page.last().sequence
                }
                assertEquals(seal.memberCount, count)
                opaque.verify(f.material, context).use { verified ->
                    var files = 0L
                    verified.visitVerified { member ->
                        if (member.kind == VaultOfflineGroupMemberKind.FILE) {
                            assertEquals(member.source, verified.fileJob(member).source)
                            assertTrue(
                                verified
                                    .payloadFile(
                                        member,
                                    ).canonicalPath
                                    .startsWith(f.directory(context).canonicalPath),
                            )
                            files++
                        }
                    }
                    assertEquals(257L, files)
                }
            }
            f.directory(context).walkTopDown().filter(File::isFile).forEach {
                assertFalse(it.readBytes().toString(Charsets.ISO_8859_1).contains("private-name-"))
            }
            val empty =
                context.copy(
                    groupId = UUID.randomUUID().toString(),
                    location = context.location.copy(kind = VaultLocationKind.SPACE_VAULT, vaultPath = ""),
                    selectedEncryptedRoot = "",
                )
            assertEquals(1L, f.build(empty) {}.memberCount)
            f.store.open(empty.owner, empty.groupId).use { it.verify(f.material, empty).close() }
        }

    @Test fun softBytePagesAllowOneLargeBoundedOpaqueDescriptorWithoutNarrowingFieldBudgets() =
        fixture { f ->
            val context = f.context
            val large =
                f.source(
                    "${context.selectedEncryptedRoot}/${f.raw("large")}",
                    "opaque-" + "x".repeat(700 * 1024),
                    true,
                )
            f.build(context) { it.appendDirectory(large) }
            f.store.open(context.owner, context.groupId).use { opaque ->
                assertEquals(1, opaque.page().size)
                val oversized = opaque.page(0)
                assertEquals(1, oversized.size)
                assertEquals(large, oversized.single().source)
                assertTrue(opaque.page(1).isEmpty())
                opaque.verify(f.material, context).use { verified ->
                    var count = 0
                    verified.visitVerified { count++ }
                    assertEquals(2, count)
                }
            }
        }

    @Test fun lateMissingReorderedCorruptOrAddedRowsWithholdAllVerifiedCallbacks() =
        fixture { f ->
            val changes =
                listOf(
                    "DELETE FROM entries WHERE seq=2",
                    "UPDATE entries SET seq=8 WHERE seq=2",
                    "UPDATE entries SET payload=X'00' WHERE seq=2",
                    "UPDATE entries SET payload=zeroblob(8*1024*1024) WHERE seq=2",
                    "INSERT INTO entries(seq,payload) SELECT 3,payload FROM entries WHERE seq=2",
                )
            changes.forEach { sql ->
                val context = f.context.copy(groupId = UUID.randomUUID().toString())
                f.build(context) {
                    it.appendDirectory(f.source("${context.selectedEncryptedRoot}/${f.raw("one")}", "one", true))
                    it.appendDirectory(f.source("${context.selectedEncryptedRoot}/${f.raw("two")}", "two", true))
                }
                f.store.open(context.owner, context.groupId).use { opaque ->
                    opaque.verify(f.material, context).use { verified ->
                        f.mutate(context, sql)
                        var callbacks = 0
                        assertThrows(OpenCloudException::class.java) { verified.visitVerified { callbacks++ } }
                        assertEquals(0, callbacks)
                    }
                    assertThrows(OpenCloudException::class.java) { opaque.verify(f.material, context) }
                }
            }
        }

    @Test fun authenticatedCallbackBindsOnlyItsMemberAndAlwaysReleasesTheBinding() =
        fixture { f ->
            val context = f.context
            f.build(context) { preparation ->
                repeat(2) { number ->
                    preparation.appendFile(
                        f.source(
                            "${context.selectedEncryptedRoot}/${f.raw("file-$number")}",
                            "file-$number",
                            false,
                        ),
                    )
                }
            }
            f.store.open(context.owner, context.groupId).use { opaque ->
                val files = opaque.page().filter { it.kind == VaultOfflineGroupMemberKind.FILE }
                val expectedPayloads =
                    files.associateWith {
                        f.store.payloads(context.owner, context.groupId).partial(opaque.fileJob(it))
                    }
                opaque.verify(f.material, context).use { verified ->
                    val stops =
                        listOf(IllegalStateException("Consumer ended"), CancellationException("Consumer cancelled"))
                    stops.forEach { stop ->
                        val failure =
                            assertThrows(Exception::class.java) {
                                verified.visitVerified { member ->
                                    if (member.kind == VaultOfflineGroupMemberKind.FILE) {
                                        assertEquals(member.source, verified.fileJob(member).source)
                                        assertEquals(expectedPayloads.getValue(member), verified.payloadFile(member))
                                        val other = files.first { it != member }
                                        val rejected =
                                            assertThrows(OpenCloudException::class.java) { verified.fileJob(other) }
                                        assertEquals(OpenCloudError.DownloadIntegrity, rejected.error)
                                        assertThrows(OpenCloudException::class.java) { verified.visitVerified {} }
                                        throw stop
                                    }
                                }
                            }
                        assertEquals(stop, failure)
                        assertEquals(files.last().source, verified.fileJob(files.last()).source)
                    }
                    var seen = 0
                    verified.visitVerified { seen++ }
                    assertEquals(3, seen)
                }
            }
        }

    @Test fun sealContextKeyAndChildDescriptorChangesCannotProduceAVerifiedPlan() =
        fixture { f ->
            val context = f.context
            f.build(
                context,
            ) { it.appendFile(f.source("${context.selectedEncryptedRoot}/${f.raw("file")}", "file", false)) }
            val root = File(f.directory(context), "seal")
            val original = root.readBytes()
            f.store.open(context.owner, context.groupId).use { opaque ->
                val wrong = f.material.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
                try {
                    val failure = assertThrows(OpenCloudException::class.java) { opaque.verify(wrong, context) }
                    assertEquals(OpenCloudError.DownloadIntegrity, failure.error)
                } finally {
                    wrong.fill(0)
                }
                assertThrows(OpenCloudException::class.java) {
                    opaque.verify(f.material, context.copy(baseOfflineRootDigest = "9".repeat(64)))
                }
                root.writeBytes(original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
                assertThrows(OpenCloudException::class.java) { opaque.verify(f.material, context) }
                root.writeBytes(original)
                val member = opaque.page().last()
                val job = opaque.fileJob(member)
                File(f.directory(context), "downloads/${job.id}/manifest").appendBytes(byteArrayOf(1))
                assertThrows(Exception::class.java) { opaque.verify(f.material, context) }
            }
        }

    @Test fun sourceTreeAndPreSealDiskOmissionRefuseAdmissionAndNeverAdmitALateChild() =
        fixture { f ->
            val context = f.context
            f.store.begin(context).use { preparation ->
                preparation.appendDirectory(f.root(context))
                assertThrows(Exception::class.java) {
                    preparation.appendDirectory(
                        f.source("${context.selectedEncryptedRoot}-other/${f.raw("out")}", "out", true),
                    )
                }
                assertThrows(OpenCloudException::class.java) {
                    preparation.appendDirectory(
                        f.source(
                            "${context.selectedEncryptedRoot}/${f.raw("missing")}/${f.raw("child")}",
                            "child",
                            true,
                        ),
                    )
                }
                preparation.appendDirectory(f.source("${context.selectedEncryptedRoot}/${f.raw("last")}", "last", true))
                var altered = false
                f.beforeSync = { directory ->
                    if (!altered && directory == f.directory(context)) {
                        altered = true
                        f.mutate(context, "DELETE FROM entries WHERE seq=1")
                    }
                }
                assertThrows(OpenCloudException::class.java) { preparation.seal(f.material) }
                assertTrue(altered)
                f.beforeSync = {}
            }
            assertFalse(f.directory(context).exists())
            val next = context.copy(groupId = UUID.randomUUID().toString())
            f.store.begin(next).use { preparation ->
                preparation.appendDirectory(f.root(next))
                preparation.seal(f.material)
                assertThrows(IllegalStateException::class.java) {
                    preparation.appendDirectory(
                        f.source("${next.selectedEncryptedRoot}/${f.raw("late")}", "late", true),
                    )
                }
                assertTrue(preparation.finishPrepared { true })
            }
        }

    @Test fun cancelRevokesAttemptsButManualRetryKeepsPlansJobsAndPartialBytesUntilExplicitDiscard() =
        fixture { f ->
            val context = f.context
            f.build(
                context,
            ) { it.appendFile(f.source("${context.selectedEncryptedRoot}/${f.raw("file")}", "file", false)) }
            val opaque = f.store.open(context.owner, context.groupId)
            val member = opaque.page().last()
            val job = opaque.fileJob(member)
            val payloads = f.store.payloads(context.owner, context.groupId)
            val partial = payloads.partial(job).apply { writeBytes(byteArrayOf(1, 2, 3)) }
            val checkpoint = payloads.checkpoint(job).apply { writeText("opaque checkpoint") }
            val attempt = f.store.beginAttempt(context.owner, context.groupId)
            f.store.cancel(context.owner, context.groupId)
            assertFalse(attempt.isActive)
            assertTrue(partial.exists())
            attempt.close()
            opaque.close()
            assertTrue(partial.exists())
            assertTrue(checkpoint.exists())
            val retry = f.store.beginAttempt(context.owner, context.groupId)
            val reader = f.store.open(context.owner, context.groupId)
            assertTrue(retry.isActive)
            f.store.cancel(context.owner, context.groupId, discardPayloads = true)
            assertTrue(partial.exists())
            retry.close()
            assertTrue(partial.exists())
            reader.close()
            assertFalse(partial.exists())
            assertFalse(checkpoint.exists())
            f.store.open(context.owner, context.groupId).use { it.verify(f.material, context).close() }
        }

    @Test fun ordinaryAccountForgetCannotRevokePrivateGroupPreparationOrCiphertextWriter() =
        fixture { f ->
            val context = f.context
            f.build(context) {}
            val source = f.source("${context.selectedEncryptedRoot}/${f.raw("file")}", "file", false)
            val payloads = f.store.payloads(context.owner, context.groupId)
            val pending = payloads.create(context.location, source, context.rootProofDigest)
            val guard = f.store.beginAttempt(context.owner, context.groupId)
            payloads.beginAttempt(pending.id, context.owner.accountId).use { groupWriter ->
                val ordinary = VaultDownloadStore(File(f.root, "ordinary"))
                val ordinaryJob = ordinary.create(context.location, source, context.rootProofDigest)
                ordinary.beginAttempt(ordinaryJob.id, context.owner.accountId).use { ordinaryWriter ->
                    ordinary.forgetAccount(context.owner.accountId)
                    assertFalse(ordinaryWriter.isActive)
                    assertFalse(ordinary.finishPrepared(ordinaryJob.id) { true })
                    assertTrue(guard.isActive)
                    assertTrue(groupWriter.isActive)
                    assertTrue(payloads.finishPrepared(pending.id) { true })
                    assertEquals(pending, f.store.payloads(context.owner, context.groupId).read(pending.id))
                }
                f.store.forget(context.owner)
                assertFalse(guard.isActive)
                assertTrue(f.directory(context).isDirectory)
                guard.close()
                assertFalse(groupWriter.isActive)
                assertFalse(f.directory(context).exists())
            }
        }

    @Test fun revokedAttemptStillExcludesAReplacementWriterUntilItsLeaseCloses() =
        fixture { f ->
            val context = f.context
            f.build(context) {}
            val first = f.store.beginAttempt(context.owner, context.groupId)
            try {
                val concurrent =
                    assertThrows(OpenCloudException::class.java) {
                        f.store.beginAttempt(context.owner, context.groupId)
                    }
                assertEquals(OpenCloudError.NotReady(1), concurrent.error)
                assertTrue(first.isActive)
                f.store.cancel(context.owner, context.groupId)
                assertFalse(first.isActive)
                val revoked =
                    assertThrows(OpenCloudException::class.java) {
                        f.store.beginAttempt(context.owner, context.groupId)
                    }
                assertEquals(OpenCloudError.NotReady(1), revoked.error)
            } finally {
                first.close()
            }
            f.store.beginAttempt(context.owner, context.groupId).use { assertTrue(it.isActive) }
        }

    @Test fun abandonmentReadersAndAccountIncarnationAbaNeverDeleteReplacementOwnership() =
        fixture { f ->
            val context = f.context
            val preparing = f.store.begin(context)
            preparing.appendDirectory(f.root(context))
            assertTrue(f.store.hasActivePreparation(context.owner, context.groupId))
            f.store.reconcile(context.owner) { false }
            assertTrue(f.directory(context).isDirectory)
            preparing.close()
            assertFalse(f.store.hasActivePreparation(context.owner, context.groupId))
            assertFalse(f.directory(context).exists())
            val old = context.copy(groupId = UUID.randomUUID().toString())
            f.build(old) {}
            val reader = f.store.open(old.owner, old.groupId)
            f.store.reconcile(old.owner) { false }
            assertTrue(f.directory(old).exists())
            reader.close()
            f.store.reconcile(old.owner) { false }
            assertFalse(f.directory(old).exists())
            val unknown = old.copy(groupId = UUID.randomUUID().toString())
            f.store.begin(unknown).use { preparation ->
                preparation.appendDirectory(f.root(unknown))
                preparation.seal(f.material)
            }
            assertTrue(f.directory(unknown).exists())
            f.store.reconcile(unknown.owner) { it == unknown.groupId }
            assertTrue(f.directory(unknown).exists())
            f.store.reconcile(unknown.owner) { false }
            assertFalse(f.directory(unknown).exists())
            val active = old.copy(groupId = UUID.randomUUID().toString())
            f.build(active) {}
            val replacement = active.copy(owner = active.owner.copy(incarnation = incarnation()))
            f.build(replacement) {}
            val oldAttempt = f.store.beginAttempt(active.owner, active.groupId)
            val newAttempt = f.store.beginAttempt(replacement.owner, replacement.groupId)
            f.store.forget(active.owner)
            assertFalse(oldAttempt.isActive)
            assertTrue(newAttempt.isActive)
            assertTrue(f.directory(active).exists())
            oldAttempt.close()
            assertFalse(f.directory(active).exists())
            assertTrue(f.directory(replacement).isDirectory)
            newAttempt.close()
            f.store.open(replacement.owner, replacement.groupId).use { it.verify(f.material, replacement).close() }
        }

    private fun fixture(block: (Fixture) -> Unit) {
        val fixture = Fixture(temporary.newFolder())
        try {
            block(fixture)
        } finally {
            fixture.cipher.close()
            fixture.material.fill(0)
        }
    }

    private class Fixture(
        val root: File,
    ) {
        val material = ByteArray(80) { it.toByte() }
        val cipher = jvmRcloneVaultCipher(material)
        val owner = VaultGroupOwner("account", incarnation(), "1".repeat(64))
        val identity = VaultIdentity(owner.accountId, "https://example.test/", "drive", "vault")
        val location =
            VaultLocation(
                owner.accountId,
                "",
                VaultLocationKind.FOLDER_VAULT,
                "drive",
                "vault",
                "root",
                identity.canonicalServer,
                "https://example.test/dav/",
                "Vault.vault",
                true,
            )
        val context =
            VaultOfflineGroupContext(
                UUID.randomUUID().toString(),
                owner,
                identity,
                location,
                location.vaultPath,
                "2".repeat(64),
                "3".repeat(64),
            )
        var beforeSync: (File) -> Unit = {}
        val store = VaultOfflineGroupPlanStore(root, jvmOfflineDurability(root) { beforeSync(it) })

        fun raw(value: String): String = cipher.encryptName("private-name-$value")

        fun root(context: VaultOfflineGroupContext) =
            source(context.selectedEncryptedRoot, context.identity.remoteVaultId, true)

        fun source(
            path: String,
            id: String,
            folder: Boolean,
        ): VaultDavEntry =
            VaultDavEntry(
                id,
                path,
                path.substringAfterLast('/'),
                folder,
                if (folder) 0 else 64,
                "\"version\"",
                location.rootWebDavUrl
                    .toHttpUrl()
                    .newBuilder()
                    .addPathSegments(path)
                    .build()
                    .toString(),
            )

        fun build(
            context: VaultOfflineGroupContext,
            append: (VaultOfflineGroupPlanStore.Preparation) -> Unit,
        ): VaultGroupSeal =
            store.begin(context).use { preparation ->
                preparation.appendDirectory(root(context))
                append(preparation)
                preparation.seal(material).also { assertTrue(preparation.finishPrepared { true }) }
            }

        fun directory(context: VaultOfflineGroupContext): File =
            File(
                root,
                "${VaultOfflineGroupPlanCodec.digest(
                    context.owner.accountId.toByteArray(),
                )}/${context.owner.incarnation}/${context.groupId}",
            )

        fun mutate(
            context: VaultOfflineGroupContext,
            sql: String,
        ) {
            SQLiteDatabase
                .openDatabase(File(directory(context), "plan.db").path, null, SQLiteDatabase.OPEN_READWRITE)
                .use { it.execSQL(sql) }
        }
    }

    private companion object {
        fun incarnation(): String = UUID.randomUUID().toString().replace("-", "")
    }
}
