package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.crypto.RcloneVaultCipher
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.network.OpenCloudException
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.security.VaultIdentity
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

/** Actual Android private SQLite, strict UTF8 and JCA seals; no server or plaintext file operations. */
@RunWith(AndroidJUnit4::class)
class VaultOfflineGroupPlanAndroidTest {
    @Test fun nativePlanPagesCompleteMembershipAndBindsOriginalPrivateChildJob() =
        fixture { f ->
            val context = f.context
            f.store.begin(context).use { preparation ->
                preparation.appendDirectory(f.source(context.selectedEncryptedRoot, "vault", true).copy(size = 4096))
                repeat(257) { number ->
                    preparation.appendDirectory(
                        f
                            .source("${context.selectedEncryptedRoot}/${f.raw(number.toString())}", "d-$number", true)
                            .copy(size = 1024),
                    )
                }
                preparation.appendFile(f.source("${context.selectedEncryptedRoot}/${f.raw("file")}", "file", false))
                val seal = preparation.seal(f.material)
                assertEquals(259L, seal.memberCount)
                assertEquals(1L, seal.fileCount)
                assertEquals(64L, seal.ciphertextBytes)
                assertTrue(preparation.finishPrepared { true })
            }
            f.store.open(context.owner, context.groupId).use { opaque ->
                var after: Long? = null
                var count = 0L
                while (true) {
                    val page = opaque.page(after)
                    if (page.isEmpty()) break
                    assertTrue(page.size in 1..128)
                    page.forEach {
                        assertEquals(count++, it.sequence)
                        if (it.kind == VaultOfflineGroupMemberKind.DIRECTORY) {
                            assertEquals(if (it.sequence == 0L) 4096L else 1024L, it.source.size)
                        }
                    }
                    after = page.last().sequence
                }
                assertEquals(259L, count)
                opaque.verify(f.material, context).use { verified ->
                    var files = 0
                    verified.visitVerified { member ->
                        if (member.kind == VaultOfflineGroupMemberKind.FILE) {
                            assertEquals(member.source, verified.fileJob(member).source)
                            assertThrows(OpenCloudException::class.java) {
                                verified.fileJob(member.copy(id = UUID.randomUUID().toString()))
                            }
                            assertThrows(OpenCloudException::class.java) { verified.visitVerified {} }
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
                    assertEquals(1, files)
                }
            }
            f.directory(context).walkTopDown().filter(File::isFile).forEach {
                assertFalse(it.readBytes().toString(Charsets.ISO_8859_1).contains("native-private-name-"))
            }
        }

    @Test fun nativeLateTailCorruptionWithholdsCallbacksAndReaderCleanupCannotCrossAccountIncarnation() =
        fixture { f ->
            val context = f.context
            f.empty(context)
            val opaque = f.store.open(context.owner, context.groupId)
            val verified = opaque.verify(f.material, context)
            try {
                SQLiteDatabase
                    .openDatabase(
                        File(f.directory(context), "plan.db").path,
                        null,
                        SQLiteDatabase.OPEN_READWRITE,
                    ).use {
                        it.execSQL("DELETE FROM entries WHERE seq=1")
                    }
                var callbacks = 0
                assertThrows(OpenCloudException::class.java) { verified.visitVerified { callbacks++ } }
                assertEquals(0, callbacks)
                f.store.reconcile(context.owner) { false }
                assertTrue(f.directory(context).exists())
            } finally {
                verified.close()
                opaque.close()
            }
            f.store.reconcile(context.owner) { false }
            assertFalse(f.directory(context).exists())

            val old = context.copy(groupId = UUID.randomUUID().toString())
            val replacement = old.copy(owner = old.owner.copy(incarnation = incarnation()))
            f.empty(old)
            f.empty(replacement)
            val previousAttempt = f.store.beginAttempt(old.owner, old.groupId)
            val replacementAttempt = f.store.beginAttempt(replacement.owner, replacement.groupId)
            try {
                f.store.cancel(old.owner, old.groupId)
                assertFalse(previousAttempt.isActive)
                assertTrue(replacementAttempt.isActive)
                assertTrue(f.directory(old).exists())
                f.store.forget(old.owner)
                assertTrue(f.directory(old).exists())
            } finally {
                previousAttempt.close()
                replacementAttempt.close()
            }
            assertFalse(f.directory(old).exists())
            assertTrue(f.directory(replacement).exists())
            f.store.open(replacement.owner, replacement.groupId).use { it.verify(f.material, replacement).close() }
        }

    private fun fixture(block: (Fixture) -> Unit) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val root = File(context.noBackupFilesDir, "offline-group-native-${UUID.randomUUID()}")
        assertTrue(root.mkdirs())
        val fixture = Fixture(root, OfflineDurability(context.noBackupFilesDir))
        try {
            block(fixture)
        } finally {
            fixture.cipher.close()
            fixture.material.fill(0)
            root.deleteRecursively()
        }
    }

    private class Fixture(
        val root: File,
        durability: OfflineDurability,
    ) {
        val material = ByteArray(80) { it.toByte() }
        val cipher = RcloneVaultCipher.fromKeyMaterial(material)
        val owner = VaultGroupOwner("native-account", incarnation(), "1".repeat(64))
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
        val store = VaultOfflineGroupPlanStore(root, durability)

        fun raw(value: String): String = cipher.encryptName("native-private-name-$value")

        fun source(
            path: String,
            id: String,
            folder: Boolean,
        ) = VaultDavEntry(
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

        fun empty(context: VaultOfflineGroupContext) =
            store.begin(context).use {
                it.appendDirectory(source(context.selectedEncryptedRoot, "vault", true))
                it.appendDirectory(source("${context.selectedEncryptedRoot}/${raw("empty")}", "empty", true))
                it.seal(material)
                assertTrue(it.finishPrepared { true })
            }

        fun directory(context: VaultOfflineGroupContext) =
            File(
                root,
                "${VaultOfflineGroupPlanCodec.digest(
                    context.owner.accountId.toByteArray(),
                )}/${context.owner.incarnation}/${context.groupId}",
            )
    }

    private companion object {
        fun incarnation(): String = UUID.randomUUID().toString().replace("-", "")
    }
}
