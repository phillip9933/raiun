package eu.opencloud.android.next.core.sync

import android.Manifest
import android.content.Context
import android.net.Uri
import android.os.Build
import android.provider.MediaStore
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.util.concurrent.CancellationException

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [Build.VERSION_CODES.S])
class OriginalMediaSourceTest {
    private val mediaUri = Uri.parse("content://${MediaStore.AUTHORITY}/external/images/media/7")
    private val mediaDocumentUri = Uri.parse("content://com.android.providers.media.documents/document/image:7")

    @Test
    fun `only image media sources are eligible for original location permission`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        assertEquals(true, isEligibleOriginalMediaSource(context, mediaUri))
        assertEquals(false, isEligibleOriginalMediaSource(context, mediaDocumentUri))
        assertEquals(
            false,
            isEligibleOriginalMediaSource(
                context,
                Uri.parse("content://com.android.externalstorage.documents/document/primary:Download/report.pdf"),
            ),
        )
        assertEquals(false, isEligibleOriginalMediaSource(context, Uri.parse("content://example.provider/item/1")))
    }

    @Test
    fun `media document images are not eligible for require original handling`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        assertEquals(false, isEligibleOriginalMediaSource(context, mediaDocumentUri))
        assertEquals(true, isEligibleOriginalMediaSource(context, mediaUri))
    }

    @Test
    fun `media document reads use the selected document uri even when location permission is granted`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        shadowOf(context as android.app.Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        val bytes = byteArrayOf(9, 4, 2, 1)
        shadowOf(context.contentResolver).registerInputStream(mediaDocumentUri, bytes.inputStream())

        assertEquals(false, requestsOriginalMedia(context, mediaDocumentUri))
        assertEquals(3L, uploadStagingExpectedLength(context, mediaDocumentUri, 3L))
        assertArrayEquals(bytes, openUploadSource(context, mediaDocumentUri).use { it.readBytes() })
    }

    @Test
    fun `external storage image stays on its selected uri even when location permission is granted`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        shadowOf(context as android.app.Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        val selectedUri = Uri.parse("content://com.android.externalstorage.documents/document/primary:DCIM/photo.jpg")
        val bytes = byteArrayOf(8, 6, 7, 5, 3, 0, 9)
        shadowOf(context.contentResolver).registerInputStream(selectedUri, bytes.inputStream())

        assertEquals(false, isEligibleOriginalMediaSource(context, selectedUri))
        assertArrayEquals(bytes, openUploadSource(context, selectedUri).use { it.readBytes() })
    }

    @Test
    fun `picker and redacted representations keep their granted uri with full permission`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        shadowOf(context as android.app.Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        val bytes = byteArrayOf(1, 2, 3)
        listOf(
            "content://media/picker/0/com.android.providers.media.photopicker/media/7",
            "content://media/external_primary/file/RUID7",
            "content://com.android.externalstorage.documents/document/primary:Download/report.pdf",
        ).forEach { value ->
            val uri = Uri.parse(value)
            shadowOf(context.contentResolver).registerInputStream(uri, bytes.inputStream())
            assertEquals(false, isEligibleOriginalMediaSource(context, uri))
            assertArrayEquals(bytes, openUploadSource(context, uri).use { it.readBytes() })
        }
    }

    @Test
    fun `granted original media permission makes provider length advisory and stages returned bytes unchanged`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        shadowOf(context as android.app.Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        val declared = 3L
        val originalBytes = byteArrayOf(1, 2, 3, 4, 5)
        val directory =
            kotlin.io.path
                .createTempDirectory()
                .toFile()
        try {
            val staged =
                stageUploadSource(
                    directory,
                    uploadStagingExpectedLength(context, mediaUri, declared),
                    { originalBytes.inputStream() },
                    { Long.MAX_VALUE },
                    {},
                )
            assertEquals(5L, staged.length())
            assertArrayEquals(originalBytes, staged.readBytes())
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun `denied permission and non media URIs retain declared length`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        val declared = 3L
        assertEquals(declared, uploadStagingExpectedLength(context, mediaUri, declared))
        shadowOf(context as android.app.Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        assertEquals(
            declared,
            uploadStagingExpectedLength(context, Uri.parse("content://example.provider/item/1"), declared),
        )
        assertEquals(declared, uploadStagingExpectedLength(context, Uri.parse("file:///tmp/item.jpg"), declared))
    }

    @Test
    fun `cancellation while opening requested original propagates without a redacted fallback`() {
        val context: Context = org.robolectric.RuntimeEnvironment.getApplication()
        shadowOf(context as android.app.Application).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        val cancellation = CancellationException("cancelled")
        val originalUri = MediaStore.setRequireOriginal(mediaUri)
        shadowOf(context.contentResolver).registerInputStream(
            originalUri,
            object : java.io.InputStream() {
                override fun read(): Int = throw cancellation

                override fun read(
                    buffer: ByteArray,
                    offset: Int,
                    length: Int,
                ): Int = throw cancellation
            },
        )
        val directory =
            kotlin.io.path
                .createTempDirectory()
                .toFile()
        try {
            val thrown =
                assertThrows(CancellationException::class.java) {
                    stageUploadSource(
                        directory,
                        uploadStagingExpectedLength(context, mediaUri, 3),
                        { openUploadSource(context, mediaUri) },
                        { Long.MAX_VALUE },
                        {},
                    )
                }
            assertSame(cancellation, thrown)
            assertEquals(false, java.io.File(directory, "payload").exists())
            assertEquals(false, java.io.File(directory, "seal").exists())
        } finally {
            directory.deleteRecursively()
        }
    }
}
