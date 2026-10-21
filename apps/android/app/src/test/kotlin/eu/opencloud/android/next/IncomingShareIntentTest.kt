package eu.opencloud.android.next

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import org.junit.Assert.assertEquals
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
}
