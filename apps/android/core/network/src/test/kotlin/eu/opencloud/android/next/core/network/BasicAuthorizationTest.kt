package eu.opencloud.android.next.core.network

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Base64

class BasicAuthorizationTest {
    @Test fun `OpenCloud basic credentials encode exact UTF8 bytes including non BMP and Latin1 characters`() {
        listOf(
            Triple("alice", "secret", "616c6963653a736563726574"),
            Triple("利用者", "秘密", "e588a9e794a8e880853ae7a798e5af86"),
            Triple("user😀", "pass🔑", "75736572f09f98803a70617373f09f9491"),
            Triple("élise", "café", "c3a96c6973653a636166c3a9"),
            Triple("e\u0301lise", "cafe\u0301", "65cc816c6973653a63616665cc81"),
        ).forEach { (username, password, expectedHex) ->
            val header = openCloudBasicAuthorization(username, password)
            assertEquals("Basic", header.substringBefore(' '))
            assertArrayEquals(
                expectedHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray(),
                Base64.getDecoder().decode(header.substringAfter(' ')),
            )
        }
    }
}
