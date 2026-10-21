package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class ProviderCollectionTest {
    @Test fun `SAF creation refuses an existing collection without adopting it`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(405))
            val client = TransferClient(OkHttpClient())
            assertThrows(TransferHttpException::class.java) {
                client.createCollection(server.url("/backup").toString(), "Bearer test", acceptExisting = false)
            }
            assertEquals("MKCOL", server.takeRequest().method)
            assertEquals(1, server.requestCount)
        }
    }

    @Test fun `SAF creation accepts only confirmed new collection`() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(201))
            TransferClient(
                OkHttpClient(),
            ).createCollection(server.url("/backup").toString(), "Bearer test", acceptExisting = false)
            assertEquals("MKCOL", server.takeRequest().method)
        }
    }
}
