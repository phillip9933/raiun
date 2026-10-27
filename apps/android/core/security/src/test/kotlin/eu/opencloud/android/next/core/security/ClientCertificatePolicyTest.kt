package eu.opencloud.android.next.core.security

import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import java.io.File
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

@RunWith(RobolectricTestRunner::class)
class ClientCertificatePolicyTest {
    @get:Rule val temporary = TemporaryFolder()

    private val key =
        object : PrivateKey {
            override fun getAlgorithm(): String = "RSA"

            override fun getFormat(): String = "PKCS#8"

            override fun getEncoded(): ByteArray = "PRIVATE_TEST_KEY_MUST_NOT_PERSIST".toByteArray()
        }

    @Test fun `binding is scoped and stores no private material`() {
        val source = FakeSource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder("certs"), source)
        val binding =
            policy.save(
                "https://cloud.example.test",
                listOf("https://idp.example.test", "https://idp.example.test:443/"),
                "test-alias",
            )

        assertEquals(setOf("https://idp.example.test"), binding.origins)
        assertEquals(binding, policy.load("https://cloud.example.test/"))
        val persisted =
            temporary.root
                .walkTopDown()
                .filter(File::isFile)
                .single()
                .readText()
        assertFalse(persisted.contains("PRIVATE_TEST_KEY_MUST_NOT_PERSIST"))
        assertFalse(persisted.contains("BEGIN CERTIFICATE"))
        assertTrue(persisted.contains("test-alias"))

        val manager = ScopedKeyManager(binding, source) { policy.load(binding.serverUrl) }
        assertEquals("test-alias", manager.select("idp.example.test", 443, arrayOf("RSA")))
        assertNull(manager.select("cloud.example.test", 443, arrayOf("RSA")))
        assertNull(manager.select("idp.example.test", 8443, arrayOf("RSA")))
        assertNull(manager.select("idp.example.test", 443, arrayOf("EC")))
        assertNotNull(manager.getPrivateKey("test-alias"))
        assertNull(manager.getPrivateKey("other"))
    }

    @Test fun `changed certificate and removed binding fail closed`() {
        val source = FakeSource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder("certs"), source)
        val binding = policy.save("https://cloud.example.test", listOf("https://idp.example.test"), "test-alias")
        val manager = ScopedKeyManager(binding, source) { policy.load(binding.serverUrl) }
        val client = policy.applyTo(OkHttpClient(), binding.serverUrl)

        source.identity = identity("synthetic-client-cert-2.pem")
        assertThrows(ClientCertificateException.Changed::class.java) {
            manager.select("idp.example.test", 443, arrayOf("RSA"))
        }
        assertThrows(ClientCertificateException.Changed::class.java) { policy.requireCurrent(binding) }
        assertThrows(ClientCertificateException.Changed::class.java) {
            client.newCall(Request.Builder().url("https://idp.example.test/token").build()).execute().close()
        }

        policy.clear(binding.serverUrl)
        assertNull(policy.load(binding.serverUrl))
        assertNull(manager.select("idp.example.test", 443, arrayOf("RSA")))
    }

    @Test fun `configured client has separate pool and never follows redirects`() {
        val source = FakeSource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder("certs"), source)
        policy.save("https://cloud.example.test", listOf("https://idp.example.test"), "test-alias")
        val base = OkHttpClient()
        val client = policy.applyTo(base, "https://cloud.example.test")
        assertFalse(client.followRedirects)
        assertFalse(client.followSslRedirects)
        assertFalse(base.connectionPool === client.connectionPool)
    }

    @Test fun `invalid origins never persist`() {
        val source = FakeSource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder("certs"), source)
        for (origin in listOf(
            "http://idp.example.test",
            "https://idp.example.test/path",
            "https://user@idp.example.test",
        )) {
            assertThrows(IllegalArgumentException::class.java) {
                policy.save("https://cloud.example.test", listOf(origin), "test-alias")
            }
        }
        assertNull(policy.load("https://cloud.example.test"))
    }

    @Test fun `oversized persisted binding is rejected before parsing`() {
        val source = FakeSource(identity("synthetic-client-cert.pem"))
        val policy = ClientCertificatePolicy(temporary.newFolder("certs"), source)
        policy.save("https://cloud.example.test", listOf("https://idp.example.test"), "test-alias")
        temporary.root
            .walkTopDown()
            .filter(File::isFile)
            .single()
            .writeBytes(ByteArray(16 * 1024 + 1))
        assertThrows(ClientCertificateException.Changed::class.java) {
            policy.load("https://cloud.example.test")
        }
    }

    private fun identity(resource: String): ClientIdentity {
        val stream = requireNotNull(javaClass.classLoader?.getResourceAsStream(resource))
        val certificate =
            stream.use {
                CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
            }
        return ClientIdentity(key, arrayOf(certificate))
    }

    private class FakeSource(
        var identity: ClientIdentity?,
    ) : ClientIdentitySource {
        override fun load(alias: String): ClientIdentity? = if (alias == "test-alias") identity else null
    }
}
