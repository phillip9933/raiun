package eu.opencloud.android.next

import android.content.ClipData
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Parcel
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class IncomingShareIntentTest {
    @Test fun `stream and clipdata duplicates become one incoming file`() {
        val uri = Uri.parse("content://sender/file.dbf")
        val intent =
            Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_STREAM, uri).apply {
                clipData = ClipData.newRawUri("file", uri)
            }
        assertEquals(listOf(uri), incomingShareUris(intent))
    }

    @Test fun `multiple incoming files retain their order`() {
        val uris = arrayListOf(Uri.parse("content://sender/a.dbf"), Uri.parse("content://sender/b.jwlibrary"))
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE).putParcelableArrayListExtra(Intent.EXTRA_STREAM, uris)
        assertEquals(uris, incomingShareUris(intent))
    }

    @Test fun `API35 rejects a receiver readable source when the caller lacked launch access`() {
        // Models a previously persisted receiver grant: it must never replace the caller check.
        val sources = listOf(Uri.parse("content://backup-readable/existing.dbf"))
        var checks = 0
        assertFalse(
            incomingShareReadAccess(sources, 35) {
                checks++
                PackageManager.PERMISSION_DENIED
            },
        )
        assertEquals(1, checks)
    }

    @Test fun `API35 accepts caller readable streams without trusting or requiring flags`() {
        val uri = Uri.parse("content://backup-readable/export.dbf")
        val share = Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_STREAM, uri)
        assertEquals(0, share.flags)
        assertTrue(incomingShareReadAccess(incomingShareUris(share), 35) { PackageManager.PERMISSION_GRANTED })
        share.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PREFIX_URI_PERMISSION)
        share.putExtra(Intent.EXTRA_REFERRER, Uri.parse("android-app://trusted.sender"))
        share.putExtra(Intent.EXTRA_REFERRER_NAME, "android-app://trusted.sender")
        assertFalse(incomingShareReadAccess(incomingShareUris(share), 35) { PackageManager.PERMISSION_DENIED })
    }

    @Test fun `every unique stream and clip URI needs its own exact profile scoped proof`() {
        val personal = Uri.parse("content://0@sender/files/a.dbf")
        val work = Uri.parse("content://10@sender/files/a.dbf")
        val share =
            Intent(Intent.ACTION_SEND_MULTIPLE)
                .putParcelableArrayListExtra(Intent.EXTRA_STREAM, arrayListOf(personal))
                .apply { clipData = ClipData.newRawUri("work", work).apply { addItem(ClipData.Item(personal)) } }
        val seen = mutableListOf<Uri>()
        assertFalse(
            incomingShareReadAccess(incomingShareUris(share), 35) {
                seen += it
                if (it == personal) PackageManager.PERMISSION_GRANTED else PackageManager.PERMISSION_DENIED
            },
        )
        assertEquals(listOf(personal, work), seen)
        assertTrue(incomingShareReadAccess(incomingShareUris(share), 35) { PackageManager.PERMISSION_GRANTED })
    }

    @Test fun `one denied item refuses the complete multiple batch`() {
        val first = Uri.parse("content://sender/one")
        val second = Uri.parse("content://sender/two")
        assertFalse(
            incomingShareReadAccess(listOf(first, second), 35) {
                if (it == first) PackageManager.PERMISSION_GRANTED else PackageManager.PERMISSION_DENIED
            },
        )
    }

    @Test fun `missing receiver access and an unrecorded URI both refuse admission`() {
        val sources = listOf(Uri.parse("content://sender/file"))
        val failures =
            listOf(
                SecurityException("synthetic"),
                IllegalArgumentException("synthetic"),
                IllegalStateException("synthetic"),
            )
        failures.forEach { failure -> assertFalse(incomingShareReadAccess(sources, 35) { throw failure }) }
        assertFalse(incomingShareReadAccess(listOf(Uri.parse("file:///synthetic")), 35) { error("must not check") })
    }

    @Test fun `recreated intent must pass a fresh caller check without a saved approval`() {
        val initial = Intent(Intent.ACTION_SEND).putExtra(Intent.EXTRA_STREAM, Uri.parse("content://sender/file"))
        assertTrue(incomingShareReadAccess(incomingShareUris(initial), 35) { PackageManager.PERMISSION_GRANTED })
        val parcel = Parcel.obtain()
        val restored =
            try {
                initial.writeToParcel(parcel, 0)
                parcel.setDataPosition(0)
                Intent.CREATOR.createFromParcel(parcel)
            } finally {
                parcel.recycle()
            }
        assertEquals(incomingShareUris(initial), incomingShareUris(restored))
        assertFalse(incomingShareReadAccess(incomingShareUris(restored), 35) { PackageManager.PERMISSION_DENIED })
    }

    @Test fun `API26 through34 preserve readable backup shares without claiming sender proof`() {
        val uri = Uri.parse("content://backup-readable/export.dbf")
        (26..34).forEach { api ->
            assertTrue(incomingShareReadAccess(listOf(uri), api) { error("No caller API exists on this version") })
        }
    }

    @Test fun `unrelated action cannot smuggle clip data into intake`() {
        val share =
            Intent(Intent.ACTION_VIEW).apply {
                clipData =
                    ClipData.newRawUri("file", Uri.parse("content://sender/file"))
            }
        assertEquals(emptyList<Uri>(), incomingShareUris(share))
    }

    @Test fun `oversized batches retain the overflow sentinel instead of silently accepting a subset`() {
        val sources = (0..102).map { Uri.parse("content://sender/$it") }
        val share =
            Intent(
                Intent.ACTION_SEND_MULTIPLE,
            ).putParcelableArrayListExtra(Intent.EXTRA_STREAM, ArrayList(sources))
        assertEquals(sources.take(101), incomingShareUris(share))
    }
}
