package eu.opencloud.android.next.ui

import android.content.ContentProvider
import android.content.ContentValues
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import eu.opencloud.android.next.core.security.VaultIdentity
import eu.opencloud.android.next.core.sync.VaultFolder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowContentResolver
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class VaultPickedTransferExecutionTest {
    private val identity = VaultViewModelRaceTest.identity
    private val folder = VaultViewModelRaceTest().folder("file.txt")
    private var queued = 0
    private var cancelDownload = false
    private val session =
        object : VaultRouteSession {
            override val identity = this@VaultPickedTransferExecutionTest.identity

            override suspend fun list(path: String): List<VaultFolder> = emptyList()

            override suspend fun preview(entry: VaultFolder) = ByteArray(0)

            override suspend fun exportVerifiedKeyMaterial() = ByteArray(0)

            override fun close() = Unit

            override suspend fun queueUpload(
                parentPath: String,
                name: String,
                source: InputStream,
                size: Long,
                mimeType: String?,
            ) {
                queued++
            }

            override suspend fun download(
                entry: VaultFolder,
                sink: OutputStream,
                maxPlaintextBytes: Long,
            ): Long {
                if (cancelDownload) {
                    currentCoroutineContext().cancel()
                    throw CancellationException()
                }
                return 0
            }
        }

    private class Owner(
        private val source: VaultFolder,
    ) : VaultPickedTransferOwner {
        var current = true
        var cancelExport = false
        var validated = 0
        var listings = 0

        override fun isCurrent(
            opened: VaultRouteSession,
            token: Long,
            account: String,
        ) = current

        override fun isCurrentTransferSession(
            opened: VaultRouteSession,
            identity: VaultIdentity,
            token: Long,
            account: String,
        ) = current

        override suspend fun verifyUploadDirectory(
            opened: VaultRouteSession,
            path: String,
        ) {
            validated++
        }

        override suspend fun revalidateExportSource(
            opened: VaultRouteSession,
            path: String,
            request: PendingVaultTransfer.Export,
        ): VaultFolder {
            if (cancelExport) {
                currentCoroutineContext().cancel()
                throw CancellationException()
            }
            return source
        }

        override suspend fun publishTransferListing(
            opened: VaultRouteSession,
            path: String,
            token: Long,
            account: String,
        ) {
            listings++
        }
    }

    @Test fun `cancelled export deletes incomplete destination under noncancellable cleanup`() =
        runTest {
            val provider = registerProvider()
            val owner = Owner(folder).apply { cancelExport = true }
            val execution = execution(owner)
            val uri = DocumentsContract.buildDocumentUri(AUTHORITY, "destination")
            val request = PendingVaultTransfer.Export(identity, "", "id", "path", "\"etag\"", 0, uri)
            val job = launch { execution.exportWithCleanup(session, request, 1, identity.accountId) }
            job.join()
            assertTrue(job.isCancelled)
            assertEquals("android:deleteDocument", provider.method)
            assertEquals(uri, provider.deletedUri)
            assertEquals(0, owner.listings)
        }

    @Test fun `stale upload after metadata does not validate queue or publish`() =
        runTest {
            val owner = Owner(folder)
            val provider = registerProvider { owner.current = false }
            val state = MutableStateFlow(VaultRouteState())
            val execution = execution(owner, state)
            execution.uploadPicked(
                session,
                PendingVaultTransfer.Upload(identity, "", Uri.parse("content://$AUTHORITY/source")),
                1,
                identity.accountId,
            )
            assertTrue(provider.cursorClosed)
            assertEquals(0, provider.opens)
            assertEquals(0, queued)
            assertEquals(0, owner.validated)
            assertEquals(0, owner.listings)
            assertFalse(state.value.preparingUpload)
            assertEquals(0, state.value.queuedUploadCount)
        }

    @Test fun `cancellation during download closes destination and deletes incomplete document`() =
        runTest {
            val provider = registerProvider()
            val owner = Owner(folder)
            cancelDownload = true
            val uri = DocumentsContract.buildDocumentUri(AUTHORITY, "download-destination")
            val request = PendingVaultTransfer.Export(identity, "", "id", "path", "\"etag\"", 0, uri)
            val reader =
                Executors.newSingleThreadExecutor { runnable ->
                    Thread(runnable, "vault-export-eof-test").apply { isDaemon = true }
                }
            try {
                val job = launch { execution(owner).exportWithCleanup(session, request, 1, identity.accountId) }
                job.join()
                assertTrue(job.isCancelled)
                assertEquals(1, provider.opens)
                assertEquals("android:deleteDocument", provider.method)
                assertEquals(uri, provider.deletedUri)
                val eof =
                    reader.submit<Int> {
                        ParcelFileDescriptor
                            .AutoCloseInputStream(
                                provider.readEnd!!,
                            ).use { it.read() }
                    }
                assertEquals(-1, eof.get(2, TimeUnit.SECONDS).toInt())
                assertEquals(0, owner.listings)
            } finally {
                runCatching { provider.writeEnd?.close() }
                runCatching { provider.readEnd?.close() }
                reader.shutdownNow()
            }
        }

    private fun execution(
        owner: Owner,
        state: MutableStateFlow<VaultRouteState> = MutableStateFlow(VaultRouteState()),
    ) = VaultPickedTransferExecution(
        RuntimeEnvironment.getApplication(),
        Dispatchers.Unconfined,
        { _, _ -> true },
        state,
        owner,
    )

    private fun registerProvider(onType: () -> Unit = {}): Provider =
        Provider(onType).also {
            it.attachInfo(RuntimeEnvironment.getApplication(), ProviderInfo().apply { authority = AUTHORITY })
            ShadowContentResolver.registerProviderInternal(AUTHORITY, it)
        }

    private class Provider(
        private val onType: () -> Unit,
    ) : ContentProvider() {
        var cursorClosed = false
        var opens = 0
        var method: String? = null
        var deletedUri: Uri? = null
        var readEnd: ParcelFileDescriptor? = null
        var writeEnd: ParcelFileDescriptor? = null

        override fun onCreate() = true

        override fun getType(uri: Uri): String {
            onType()
            return "text/plain"
        }

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            selectionArgs: Array<out String>?,
            sortOrder: String?,
        ): Cursor =
            object : MatrixCursor(arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)) {
                override fun close() {
                    cursorClosed = true
                    super.close()
                }
            }.apply { addRow(arrayOf("file.txt", 1L)) }

        override fun openFile(
            uri: Uri,
            mode: String,
        ): ParcelFileDescriptor {
            opens++
            val pipe = ParcelFileDescriptor.createPipe()
            readEnd = pipe[0]
            writeEnd = pipe[1]
            return pipe[1]
        }

        override fun call(
            method: String,
            arg: String?,
            extras: Bundle?,
        ): Bundle {
            this.method = method
            @Suppress("DEPRECATION")
            deletedUri = extras?.getParcelable("uri")
            return Bundle()
        }

        override fun insert(
            uri: Uri,
            values: ContentValues?,
        ): Uri? = null

        override fun delete(
            uri: Uri,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            selectionArgs: Array<out String>?,
        ) = 0
    }

    companion object {
        private const val AUTHORITY = "vault-picked-execution.test"
    }
}
