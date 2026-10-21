package eu.opencloud.android.next.core.documentsprovider

import android.os.ParcelFileDescriptor
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import eu.opencloud.android.next.core.database.AccountEntity
import eu.opencloud.android.next.core.database.FileBrowserDatabase
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.database.SpaceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.sync.clearTemporaryCopies
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CachedDocumentReadDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun nativeDescriptorCloseReleasesTemporaryCopyLease() =
        runBlocking(Dispatchers.IO) {
            val database = FileBrowserDatabase.create(context)
            val accountId = "device-test-${UUID.randomUUID()}"
            val spaceId = "device-test-${UUID.randomUUID()}"
            val resourceId = "device-test-${UUID.randomUUID()}"
            val pinnedId = "device-test-${UUID.randomUUID()}"
            val directory = resourceCacheDirectory(context.filesDir, accountId, spaceId).apply { mkdirs() }
            val temporaryFile = File(directory, "temporary-${UUID.randomUUID()}.bin").apply { writeText("temporary") }
            val pinnedFile = File(directory, "pinned-${UUID.randomUUID()}.bin").apply { writeText("pinned") }
            val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
            var descriptor: ParcelFileDescriptor? = null
            try {
                database.accountDao().upsert(
                    AccountEntity(
                        accountId,
                        "https://device-test.invalid",
                        "device-test",
                        "Device test",
                        "BASIC",
                        false,
                    ),
                )
                database.spaceDao().insert(
                    SpaceEntity(
                        accountId,
                        spaceId,
                        "Device test",
                        "personal",
                        null,
                        null,
                        "root",
                        "https://device-test.invalid/dav/$spaceId",
                        null,
                        null,
                    ),
                )
                database.resourceDao().insertAll(
                    listOf(
                        cachedResource(accountId, spaceId, resourceId, temporaryFile, pinned = false),
                        cachedResource(accountId, spaceId, pinnedId, pinnedFile, pinned = true),
                    ),
                )

                descriptor = openCachedRead(temporaryFile, scope) {}
                assertTrue("The platform descriptor should remain open", descriptor.fileDescriptor.valid())
                assertEquals(0, clearTemporaryCopies(context))
                assertTrue("An open native descriptor must keep its leased file", temporaryFile.exists())
                assertTrue("The unrelated pinned fixture must remain", pinnedFile.exists())

                assertEquals(
                    "temporary",
                    ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { it.readText() },
                )
                descriptor = null

                withTimeout(CLOSE_RECLAIM_TIMEOUT_MILLIS) {
                    while (temporaryFile.exists()) {
                        clearTemporaryCopies(context)
                        if (temporaryFile.exists()) delay(RETRY_DELAY_MILLIS)
                    }
                }
                assertFalse(
                    "The temporary file should be reclaimed after native close releases its lease",
                    temporaryFile.exists(),
                )
                assertTrue("Pinned local copies remain protected", pinnedFile.exists())
            } finally {
                descriptor?.close()
                scope.cancel()
                database.resourceDao().deleteAll(accountId, spaceId)
                database.spaceDao().deleteForAccount(accountId)
                database.accountDao().delete(accountId)
                temporaryFile.delete()
                pinnedFile.delete()
                directory.delete()
            }
        }

    private fun cachedResource(
        accountId: String,
        spaceId: String,
        resourceId: String,
        file: File,
        pinned: Boolean,
    ) = ResourceEntity(
        accountId = accountId,
        spaceId = spaceId,
        remoteId = resourceId,
        parentId = null,
        path = "/$resourceId",
        name = file.name,
        kind = ResourceKind.FILE,
        mimeType = "application/octet-stream",
        sizeBytes = file.length(),
        eTag = "\"device-test\"",
        modifiedAtEpochMillis = 0,
        createdAtEpochMillis = 0,
        offlinePinned = pinned,
        hasLocalCopy = true,
        localPath = file.absolutePath,
    )

    private companion object {
        const val CLOSE_RECLAIM_TIMEOUT_MILLIS = 5_000L
        const val RETRY_DELAY_MILLIS = 50L
    }
}
