package eu.opencloud.android.next.core.documentsprovider

import android.content.Intent
import android.provider.DocumentsContract
import eu.opencloud.android.next.core.sync.SharedDownloadFile
import eu.opencloud.android.next.core.sync.SharedDownloadRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment

@RunWith(RobolectricTestRunner::class)
class SharedFileIntentTest {
    @Test fun externalViewGrantsOnlyReadAccessToTheScopedDocument() {
        val context = RuntimeEnvironment.getApplication()
        val request =
            SharedDownloadRequest("account", "share", "scope", SharedDownloadFile("file", "/private-name", 5, "v1"))
        val intent = sharedFileViewIntent(context, request, "image/jpeg")
        assertEquals(Intent.ACTION_VIEW, intent.action)
        assertEquals(Intent.FLAG_GRANT_READ_URI_PERMISSION, intent.flags)
        assertEquals("image/jpeg", intent.type)
        assertEquals("content", intent.data?.scheme)
        assertEquals("${context.packageName}.documents", intent.data?.authority)
        assertEquals(intent.data, intent.clipData?.getItemAt(0)?.uri)
        assertFalse(intent.data.toString().contains("private-name"))
        val id = SharedDocumentId.decode(DocumentsContract.getDocumentId(requireNotNull(intent.data)))
        assertEquals(SharedDocumentId("account", "share", "scope", "file"), id)
    }
}
