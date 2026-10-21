package eu.opencloud.android.next

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import eu.opencloud.android.next.core.database.ResourceEntity
import eu.opencloud.android.next.core.model.ResourceKind
import eu.opencloud.android.next.core.model.fileMimeType
import eu.opencloud.android.next.core.model.resourceCacheDirectory
import eu.opencloud.android.next.core.sync.exportCachedFile
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.shadows.ShadowContentResolver
import java.io.File

@RunWith(RobolectricTestRunner::class)
class FileExportTest {
    @Test fun applicationDeclaresUserConfirmedApkInstallationPermission() {
        val context = RuntimeEnvironment.getApplication()
        val info =
            context.packageManager.getPackageInfo(
                context.packageName,
                android.content.pm.PackageManager.GET_PERMISSIONS,
            )
        assertTrue(info.requestedPermissions.orEmpty().contains(android.Manifest.permission.REQUEST_INSTALL_PACKAGES))
    }

    @Test fun apkMimeOverridesGenericOrZipServerMetadata() {
        assertEquals("application/vnd.android.package-archive", fileMimeType("App.APK", "application/zip"))
        assertEquals("application/pdf", fileMimeType("report.pdf", "application/octet-stream"))
        assertEquals("application/octet-stream", fileMimeType("unknown", null))
    }

    @Test fun exportCopiesAndVerifiesBytesWithoutDeletingAppCache() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val directory = resourceCacheDirectory(context.filesDir, "a", "s").apply { mkdirs() }
            val source = File(directory, "cached").apply { writeText("hello") }
            val destination = File(context.cacheDir, "exported")
            registerProvider(ExportProvider(destination))
            exportCachedFile(context, resource(source), Uri.parse("content://export.test/file"))
            assertEquals("hello", destination.readText())
            assertTrue(source.exists())
        }

    @Test fun mismatchedDestinationFailsVerificationAndKeepsCache() =
        runBlocking {
            val context = RuntimeEnvironment.getApplication()
            val source =
                File(resourceCacheDirectory(context.filesDir, "a", "s").apply { mkdirs() }, "cached")
                    .apply { writeText("hello") }
            val destination = File(context.cacheDir, "exported")
            val corrupt = File(context.cacheDir, "corrupt").apply { writeText("other") }
            registerProvider(ExportProvider(destination, corrupt))
            try {
                exportCachedFile(context, resource(source), Uri.parse("content://export.test/file"))
                org.junit.Assert.fail("Export must fail when readback differs")
            } catch (_: IllegalStateException) {
                assertEquals("hello", source.readText())
            }
        }

    private fun registerProvider(provider: ExportProvider) {
        provider.attachInfo(
            RuntimeEnvironment.getApplication(),
            android.content.pm
                .ProviderInfo()
                .apply { authority = "export.test" },
        )
        ShadowContentResolver.registerProviderInternal("export.test", provider)
    }

    private fun resource(file: File) =
        ResourceEntity(
            "a",
            "s",
            "r",
            null,
            "/hello.txt",
            "hello.txt",
            ResourceKind.FILE,
            "text/plain",
            5,
            "v1",
            0,
            0,
            hasLocalCopy = true,
            localPath = file.absolutePath,
        )

    private class ExportProvider(
        private val target: File,
        private val readback: File = target,
    ) : ContentProvider() {
        override fun onCreate() = true

        override fun getType(uri: Uri) = "text/plain"

        override fun openFile(
            uri: Uri,
            mode: String,
        ): ParcelFileDescriptor =
            ParcelFileDescriptor.open(if (mode == "r") readback else target, ParcelFileDescriptor.parseMode(mode))

        override fun query(
            uri: Uri,
            projection: Array<out String>?,
            selection: String?,
            args: Array<out String>?,
            sort: String?,
        ): Cursor? = null

        override fun insert(
            uri: Uri,
            values: ContentValues?,
        ): Uri? = null

        override fun delete(
            uri: Uri,
            selection: String?,
            args: Array<out String>?,
        ) = 0

        override fun update(
            uri: Uri,
            values: ContentValues?,
            selection: String?,
            args: Array<out String>?,
        ) = 0
    }
}
