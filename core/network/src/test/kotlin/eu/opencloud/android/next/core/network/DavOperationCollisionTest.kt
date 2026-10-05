package eu.opencloud.android.next.core.network

import okhttp3.OkHttpClient
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Test

class DavOperationCollisionTest {
    @Test fun unchangedSourceAndExistingDestinationIsAConflictWithoutRetryingMutation() {
        checkCollision("v1", true, OpenCloudError.Conflict)
    }

    @Test fun changedSourceRemainsAPreconditionFailure() {
        checkCollision("v2", true, OpenCloudError.PreconditionFailed)
    }

    @Test fun missingDestinationDoesNotMisclassifyOtherPreconditionFailures() {
        checkCollision("v1", false, OpenCloudError.PreconditionFailed)
    }

    private fun checkCollision(
        sourceVersion: String,
        destinationExists: Boolean,
        expected: OpenCloudError,
    ) {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(412))
            server.enqueue(properties("/source", sourceVersion))
            if (sourceVersion ==
                "v1"
            ) {
                server.enqueue(
                    if (destinationExists) properties("/target", "target") else MockResponse().setResponseCode(404),
                )
            }
            val client = DavOperationClient(OkHttpClient())
            try {
                client.mutate(
                    server.url("source").toString(),
                    server.url("target").toString(),
                    true,
                    "\"v1\"",
                    "Bearer synthetic",
                )
                fail("Conditional failure expected")
            } catch (failure: Exception) {
                assertEquals(expected, failure.toOpenCloudError())
            }
            val mutation = server.takeRequest()
            assertEquals("MOVE", mutation.method)
            assertEquals("F", mutation.getHeader("Overwrite"))
            assertEquals("\"v1\"", mutation.getHeader("If-Match"))
            assertEquals("PROPFIND", server.takeRequest().method)
            if (sourceVersion == "v1") assertEquals("PROPFIND", server.takeRequest().method)
            assertEquals(if (sourceVersion == "v1") 3 else 2, server.requestCount)
        }
    }

    private fun properties(
        path: String,
        version: String,
    ) = MockResponse().setResponseCode(207).setBody(
        "<d:multistatus xmlns:d=\"DAV:\"><d:response><d:href>$path</d:href><d:propstat><d:prop>" +
            "<d:resourcetype/><d:getcontentlength>1</d:getcontentlength><d:getetag>\"$version\"</d:getetag>" +
            "</d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>",
    )
}
