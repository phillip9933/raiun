package eu.opencloud.android.next.core.sync

import android.database.sqlite.SQLiteDatabase
import eu.opencloud.android.next.core.database.VaultGroupOwner
import eu.opencloud.android.next.core.network.VaultDavEntry
import eu.opencloud.android.next.core.security.VaultIdentity
import okhttp3.HttpUrl.Companion.toHttpUrl
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.io.IOException
import java.util.UUID
import java.util.concurrent.ExecutionException
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

@RunWith(RobolectricTestRunner::class)
class VaultOfflineGroupPlanThreadAffinityTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun createReturnsWithoutThreadBoundTransaction() = assertWriterTransactionFree()

    @Test fun failedBatchRollsBackRowsAndFreezesPreparation() {
        assertWriterTransactionFree()
        val planRoot = temporary.newFolder("rollback-thread-hop-plan")
        val context = context()
        val store = VaultOfflineGroupPlanStore(planRoot, jvmOfflineDurability(planRoot))
        val injected = IOException("synthetic plan cancellation")
        var armed = false
        var activeChecks = 0
        val preparation =
            store.begin(context) {
                if (armed && ++activeChecks == 3) throw injected
            }

        try {
            preparation.appendDirectory(entry(context, context.selectedEncryptedRoot, "vault", folder = true))
            preparation.appendDirectory(
                entry(context, "${context.selectedEncryptedRoot}/child", "source-child", folder = true),
            )
            armed = true

            assertSame(injected, assertThrows(IOException::class.java) { preparation.flush() })
            assertEquals(3, activeChecks)
            SQLiteDatabase
                .openDatabase(
                    File(planDirectory(planRoot, context), "plan.db").path,
                    null,
                    SQLiteDatabase.OPEN_READONLY,
                ).use { database ->
                    database.rawQuery("SELECT COUNT(*) FROM entries", null).use { cursor ->
                        assertTrue(cursor.moveToFirst())
                        assertEquals(0, cursor.getInt(0))
                    }
                    database.rawQuery("SELECT COUNT(*) FROM tree", null).use { cursor ->
                        assertTrue(cursor.moveToFirst())
                        assertEquals(0, cursor.getInt(0))
                    }
                }
            assertThrows(IllegalStateException::class.java) {
                preparation.appendDirectory(
                    entry(context, "${context.selectedEncryptedRoot}/later", "source-later", folder = true),
                )
            }
            assertThrows(IllegalStateException::class.java) { preparation.flush() }
            assertThrows(IllegalStateException::class.java) { preparation.seal(ByteArray(80) { it.toByte() }) }
        } finally {
            preparation.close()
        }

        assertFalse(store.hasActivePreparation(context.owner, context.groupId))
        assertFalse(planDirectory(planRoot, context).exists())
    }

    @Test fun preparationCanAppendFlushSealAndReadAcrossBoundedThreadHops() {
        assertWriterTransactionFree()
        val planRoot = temporary.newFolder("thread-hop-plan")
        val context = context()
        val store = VaultOfflineGroupPlanStore(planRoot, jvmOfflineDurability(planRoot))
        val preparation =
            callOn("plan-begin") {
                store.begin(context)
            }

        try {
            callOn("plan-append-root") {
                preparation.appendDirectory(entry(context, context.selectedEncryptedRoot, "vault", folder = true))
            }

            callOn("plan-append-before-explicit-flush") {
                for (index in 1..126) {
                    preparation.appendDirectory(
                        entry(
                            context,
                            "${context.selectedEncryptedRoot}/child-$index",
                            "source-$index",
                            folder = true,
                        ),
                    )
                }
            }
            callOn("plan-explicit-flush") { preparation.flush() }

            callOn("plan-append-through-automatic-batch-flush") {
                for (index in 127..254) {
                    preparation.appendDirectory(
                        entry(
                            context,
                            "${context.selectedEncryptedRoot}/child-$index",
                            "source-$index",
                            folder = true,
                        ),
                    )
                }
            }
            callOn("plan-explicit-flush-after-automatic-batch") { preparation.flush() }
            callOn("plan-append-final-pending-record") {
                preparation.appendDirectory(
                    entry(
                        context,
                        "${context.selectedEncryptedRoot}/child-255",
                        "source-255",
                        folder = true,
                    ),
                )
            }

            val seal = callOn("plan-seal-and-scan") { preparation.seal(ByteArray(80) { it.toByte() }) }
            assertEquals(256L, seal.memberCount)
            assertEquals(0L, seal.fileCount)
            assertEquals(0L, seal.ciphertextBytes)
            assertTrue(callOn("plan-finish-prepared") { preparation.finishPrepared { true } })

            callOn("plan-open-reader") {
                store.open(context.owner, context.groupId).use { opaque ->
                    val verified = callOn("plan-verify") { opaque.verify(ByteArray(80) { it.toByte() }, context) }
                    try {
                        val visited =
                            callOn("plan-visit-verified") {
                                var count = 0L
                                verified.visitVerified { count++ }
                                count
                            }
                        assertEquals(256L, visited)
                        assertEquals(256L, seal.memberCount)
                    } finally {
                        callOn("plan-close-verified") { verified.close() }
                    }
                }
            }
        } finally {
            callOn("plan-close-preparation") { preparation.close() }
        }
    }

    @Test fun abortClosesFlushedPlanAndRemovesItAcrossBoundedThreadHops() {
        assertWriterTransactionFree()
        val planRoot = temporary.newFolder("aborted-thread-hop-plan")
        val context = context()
        val store = VaultOfflineGroupPlanStore(planRoot, jvmOfflineDurability(planRoot))
        val preparation = callOn("abort-plan-begin") { store.begin(context) }
        val directory = planDirectory(planRoot, context)

        try {
            callOn("abort-plan-append-root") {
                preparation.appendDirectory(entry(context, context.selectedEncryptedRoot, "vault", folder = true))
            }
            callOn("abort-plan-append-child") {
                preparation.appendDirectory(
                    entry(
                        context,
                        "${context.selectedEncryptedRoot}/child",
                        "source-child",
                        folder = true,
                    ),
                )
            }
            callOn("abort-plan-flush") { preparation.flush() }
            callOn("abort-plan-close") { preparation.close() }

            assertFalse(store.hasActivePreparation(context.owner, context.groupId))
            assertFalse(directory.exists())
        } finally {
            callOn("abort-plan-cleanup") { preparation.close() }
        }
    }

    private fun assertWriterTransactionFree() {
        val records = VaultOfflineGroupPlanDatabase(temporary.newFile("plan-guard-${UUID.randomUUID()}.db"))
        val owner =
            Executors.newSingleThreadExecutor { task ->
                Thread(task, "offline-plan-database-owner").apply { isDaemon = true }
            }
        val created =
            owner.submit {
                var database: SQLiteDatabase? = null
                try {
                    val connection = records.create()
                    database = connection
                    assertFalse(
                        "The plan database must not return with a transaction owned by its creator thread.",
                        connection.inTransaction(),
                    )
                } finally {
                    database?.let { connection ->
                        try {
                            if (connection.inTransaction()) connection.endTransaction()
                        } finally {
                            if (connection.isOpen) connection.close()
                        }
                    }
                }
            }

        try {
            created.get(5, TimeUnit.SECONDS)
        } catch (failure: ExecutionException) {
            throw failure.cause ?: failure
        } catch (_: TimeoutException) {
            created.cancel(true)
            throw AssertionError("Plan database creation exceeded the bounded owner-thread wait.")
        } finally {
            owner.shutdownNow()
            owner.awaitTermination(1, TimeUnit.SECONDS)
        }
    }

    private fun context(): VaultOfflineGroupContext {
        val owner = VaultGroupOwner("account", UUID.randomUUID().toString().replace("-", ""), "1".repeat(64))
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
                "https://example.test/dav/files/",
                "Secret.vault",
                true,
            )
        return VaultOfflineGroupContext(
            UUID.randomUUID().toString(),
            owner,
            identity,
            location,
            location.vaultPath,
            "2".repeat(64),
            "3".repeat(64),
        )
    }

    private fun entry(
        context: VaultOfflineGroupContext,
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
            context.location.rootWebDavUrl
                .toHttpUrl()
                .newBuilder()
                .addPathSegments(path)
                .build()
                .toString(),
        )

    private fun planDirectory(
        root: File,
        context: VaultOfflineGroupContext,
    ): File =
        File(
            root,
            "${VaultOfflineGroupPlanCodec.digest(
                context.owner.accountId.toByteArray(),
            )}/${context.owner.incarnation}/${context.groupId}",
        )

    private fun <T> callOn(
        name: String,
        action: () -> T,
    ): T {
        val executor =
            Executors.newSingleThreadExecutor { task ->
                Thread(task, name).apply { isDaemon = true }
            }
        val future = executor.submit<T> { action() }
        try {
            return try {
                future.get(5, TimeUnit.SECONDS)
            } catch (failure: ExecutionException) {
                throw failure.cause ?: failure
            } catch (_: TimeoutException) {
                future.cancel(true)
                throw AssertionError("Operation on $name exceeded the bounded wait.")
            }
        } finally {
            executor.shutdownNow()
            executor.awaitTermination(1, TimeUnit.SECONDS)
        }
    }
}
