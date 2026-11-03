package eu.opencloud.android.next

import android.content.pm.ApplicationInfo
import android.security.NetworkSecurityPolicy
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** Uses Android's installed-app policy; no DNS, network requests or server changes. */
class NetworkSecurityPolicyAndroidTest {
    @Test fun cleartextIsDeniedExceptExactDebugLoopbackHosts() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val debug = context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0
        val policy = NetworkSecurityPolicy.getInstance()
        assertFalse(policy.isCleartextTrafficPermitted)
        listOf("cloud.example", "192.168.3.1", "10.0.2.2", "sub.localhost", "127.0.0.2").forEach { host ->
            assertFalse("Cleartext unexpectedly permitted for $host", policy.isCleartextTrafficPermitted(host))
        }
        listOf("localhost", "127.0.0.1", "::1").forEach { host ->
            assertEquals("Unexpected loopback policy for $host", debug, policy.isCleartextTrafficPermitted(host))
        }
    }
}
