package eu.opencloud.android.next.core.security

import org.junit.rules.ExternalResource
import org.robolectric.shadow.api.Shadow
import java.lang.reflect.Field

/** Keeps Libcore's cached OS instance consistent with this test's custom shadow mapping. */
class DirectoryLinuxModelRule : ExternalResource() {
    private lateinit var osField: Field
    private var previousOs: Any? = null

    override fun before() {
        osField = Class.forName("libcore.io.Libcore").getDeclaredField("os").apply { isAccessible = true }
        previousOs = osField.get(null)
        val linux =
            Class
                .forName("libcore.io.Linux")
                .getDeclaredConstructor()
                .apply { isAccessible = true }
                .newInstance()
        check(Shadow.extract<Any>(linux) is DirectoryAwareLinuxShadow)
        val osType = Class.forName("libcore.io.Os")
        val wrapper =
            Class
                .forName("libcore.io.BlockGuardOs")
                .getDeclaredConstructor(osType)
                .apply { isAccessible = true }
                .newInstance(linux)
        osField.set(null, wrapper)
    }

    override fun after() {
        osField.set(null, previousOs)
        previousOs = null
    }
}
