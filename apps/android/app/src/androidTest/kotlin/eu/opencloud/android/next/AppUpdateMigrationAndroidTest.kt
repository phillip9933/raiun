package eu.opencloud.android.next

import android.content.Context
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import io.github.phillip9933.appupdater.UpdateConfig
import io.github.phillip9933.appupdater.UpdateManager
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test

/** Opt-in check of a disposable 0.1.3 updater state after installing the 0.2.0 host APK. */
class AppUpdateMigrationAndroidTest {
    @Test fun priorSyntheticReadyStateSurvivesNamespaceChange() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("runUpdaterMigrationProbe") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertTrue(
            Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
                Build.PRODUCT.startsWith("sdk", ignoreCase = true),
        )
        val stateName = "android_updates_synthetic_install_journey"
        val oldBootstrap = context.getSharedPreferences("dev.rogers.appupdater.bootstrap", Context.MODE_PRIVATE)
        assertEquals(stateName, oldBootstrap.getString("state_name", null))
        val prior = context.getSharedPreferences(stateName, Context.MODE_PRIVATE)
        val priorTag = requireNotNull(prior.getString("ready_tag", null))
        assertEquals(false, prior.getBoolean("automatic", true))
        assertEquals(false, prior.getBoolean("wifi", true))

        val manager =
            UpdateManager.get(
                context,
                UpdateConfig(
                    owner = "phillip9933",
                    repository = "raiun",
                    tagPrefix = "android-v",
                    assetPrefix = "raiun-android-",
                    legacyVersions = setOf("0.9.3"),
                    legacyAssetPrefix = "raiun-",
                    stateName = stateName,
                ),
            )
        manager.initialize()
        val restored =
            runBlocking {
                withTimeout(15_000) { manager.state.first { it.ready || it.error != null } }
            }
        assertTrue("Ready restoration failed: ${restored.error}", restored.ready)
        assertEquals(priorTag, restored.available?.tag)
        assertEquals(false, restored.automaticChecks)
        assertEquals(false, restored.wifiDownload)
        val normal = context.getSharedPreferences("android_updates", Context.MODE_PRIVATE)
        assertEquals(false, normal.getBoolean("automatic", true))
        assertEquals(true, normal.getBoolean("wifi", false))
        assertEquals("BETA", normal.getString("channel", null))
        val newBootstrap =
            context.getSharedPreferences("io.github.phillip9933.appupdater.bootstrap", Context.MODE_PRIVATE)
        assertEquals(stateName, newBootstrap.getString("state_name", null))
        assertEquals(stateName, oldBootstrap.getString("state_name", null))
    }
}
