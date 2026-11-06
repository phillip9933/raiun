package eu.opencloud.android.next.core.security

import android.system.Os
import android.system.OsConstants
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.shadow.api.Shadow

/** Verifies the host descriptor model only; native migration probes cover real durability. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35], shadows = [DirectoryAwareLinuxShadow::class])
class DirectoryAwareLinuxShadowTest {
    @get:Rule val directoryModel = DirectoryLinuxModelRule()

    @get:Rule val temporary = TemporaryFolder()

    @Test fun `installed directory model opens stats syncs and closes descriptors`() {
        val constructor = Class.forName("libcore.io.Linux").getDeclaredConstructor()
        constructor.isAccessible = true
        val linux = constructor.newInstance()
        val installed = Shadow.extract<Any>(linux)
        assertTrue("Directory shadow must be installed", installed is DirectoryAwareLinuxShadow)
        val directory = temporary.newFolder("synthetic-directory")
        val mode = (installed as DirectoryAwareLinuxShadow).stat(directory.path).st_mode
        assertTrue("stat(path) must identify a directory; mode=$mode", OsConstants.S_ISDIR(mode))
        val descriptor = Os.open(directory.path, OsConstants.O_RDONLY, 0)
        try {
            assertTrue("fstat(fd) must identify a directory", OsConstants.S_ISDIR(Os.fstat(descriptor).st_mode))
            Os.fsync(descriptor)
        } finally {
            Os.close(descriptor)
        }
    }
}
