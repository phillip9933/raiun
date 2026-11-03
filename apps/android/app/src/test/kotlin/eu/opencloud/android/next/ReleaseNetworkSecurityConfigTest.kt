package eu.opencloud.android.next

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory

/** Debug instrumentation cannot establish what the release resource permits. */
class ReleaseNetworkSecurityConfigTest {
    @Test fun releaseManifestUsesCleartextDenyingSystemTrustConfiguration() {
        val factory = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
        val parser = factory.newDocumentBuilder()
        val manifest = parser.parse(File("src/main/AndroidManifest.xml"))
        val application = manifest.getElementsByTagName("application").item(0) as org.w3c.dom.Element
        assertEquals(
            "@xml/network_security_config",
            application.getAttributeNS("http://schemas.android.com/apk/res/android", "networkSecurityConfig"),
        )
        val config = parser.parse(File("src/main/res/xml/network_security_config.xml"))
        val base = config.getElementsByTagName("base-config")
        assertEquals(1, base.length)
        assertEquals("false", (base.item(0) as org.w3c.dom.Element).getAttribute("cleartextTrafficPermitted"))
        assertEquals(0, config.getElementsByTagName("domain-config").length)
        assertEquals(0, config.getElementsByTagName("debug-overrides").length)
        val certificates = config.getElementsByTagName("certificates")
        assertEquals(1, certificates.length)
        assertEquals("system", (certificates.item(0) as org.w3c.dom.Element).getAttribute("src"))
        // A release-specific overlay would replace the checked main resource.
        assertFalse(File("src/release/res/xml/network_security_config.xml").exists())
    }
}
