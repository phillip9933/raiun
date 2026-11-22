package eu.opencloud.android.next

import android.content.Context
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import io.github.phillip9933.appupdater.AndroidUpdateChannel
import io.github.phillip9933.appupdater.AndroidUpdateRelease
import io.github.phillip9933.appupdater.UpdateConfig
import io.github.phillip9933.appupdater.UpdateManager
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/** Opt-in upgrade of an actual 0.2.1 host's synthetic state on a disposable emulator. */
class AppUpdate100MigrationAndroidTest {
    /** Run against the preserved 0.2.1 target APK, then replace only that APK with the new host. */
    @Test fun seedPrior021SyntheticState() {
        assumeTrue(InstrumentationRegistry.getArguments().getString("seedUpdater021MigrationProbe") == "true")
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assertDisposable(context)
        val config = config()
        val bootstrap = context.getSharedPreferences("io.github.phillip9933.appupdater.bootstrap", Context.MODE_PRIVATE)
        assertTrue("Use a fresh disposable host", bootstrap.all.isEmpty())
        assertFalse(context.packageManager.canRequestPackageInstalls())
        val file = File.createTempFile("synthetic-021-migration-", ".apk", context.cacheDir)
        try {
            instrumentation.context.assets.open("updater/valid-higher.apk").use { input ->
                file.outputStream().use { input.copyTo(it) }
            }
            val digest =
                MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
            val release =
                AndroidUpdateRelease(
                    tag = "android-v99.0.0",
                    notes = "Synthetic SDK migration",
                    assetName = "raiun-android-99.0.0.apk",
                    downloadUrl =
                        "https://github.com/phillip9933/raiun/releases/download/" +
                            "android-v99.0.0/raiun-android-99.0.0.apk",
                    sizeBytes = file.length(),
                    sha256 = digest,
                    publishedAt = null,
                )
            val prefs = context.getSharedPreferences(config.stateName, Context.MODE_PRIVATE)
            check(
                prefs
                    .edit()
                    .clear()
                    .putBoolean("automatic", false)
                    .putBoolean("wifi", false)
                    .putString("channel", "BETA")
                    .putString("release_channel", "BETA")
                    .putString("release_tag", release.tag)
                    .putString("release_notes", release.notes)
                    .putString("release_asset", release.assetName)
                    .putString("release_url", release.downloadUrl)
                    .putLong("release_size", release.sizeBytes)
                    .putString("release_sha", digest)
                    .putString("ready_tag", release.tag)
                    .putString("ready_sha", digest)
                    .putString("dismissed_tag", release.tag)
                    .commit(),
            )
            val manager = UpdateManager.get(context, config)
            val apkMethod =
                manager.javaClass.declaredMethods.single {
                    it.name.startsWith("apkFile") &&
                        it.parameterTypes.contentEquals(arrayOf(AndroidUpdateRelease::class.java, String::class.java))
                }
            val cached = apkMethod.apply { isAccessible = true }.invoke(manager, release, digest) as File
            assertTrue(cached.parentFile?.isDirectory == true || cached.parentFile?.mkdirs() == true)
            file.copyTo(cached, overwrite = true)
            manager.initialize()
            val restored =
                runBlocking {
                    withTimeout(15_000) { manager.state.first { it.ready || it.error != null } }
                }
            assertTrue("Old SDK did not verify the seed: ${restored.error}", restored.ready)
            assertFalse(restored.offer)
            File(context.filesDir, "synthetic-updater-021-userdata.txt")
                .writeText("Raiun updater 0.2.1 retained data\n")
            assertFalse(prefs.contains("handoff_file"))
            assertEquals(installedVersionCode(context), bootstrap.all["host_version_code"])
        } finally {
            file.delete()
        }
    }

    @Test fun prior021StateRetainsChoicesAndRequiresForegroundInstallerHandoff() {
        val arguments = InstrumentationRegistry.getArguments()
        assumeTrue(arguments.getString("runUpdater100MigrationProbe") == "true")
        assertEquals("0.2.1", arguments.getString("updaterMigrationFrom"))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assertDisposable(context)
        val config = config()
        val bootstrap = context.getSharedPreferences("io.github.phillip9933.appupdater.bootstrap", Context.MODE_PRIVATE)
        assertEquals(config.stateName, bootstrap.getString("state_name", null))
        val prefs = context.getSharedPreferences(config.stateName, Context.MODE_PRIVATE)
        val prior = prefs.all.toMap()
        assertEquals(false, prior["automatic"])
        assertEquals(false, prior["wifi"])
        assertEquals("BETA", prior["channel"])
        assertEquals("android-v99.0.0", prior["ready_tag"])
        assertEquals(prior["ready_tag"], prior["dismissed_tag"])
        assertFalse("The old host must not have handed off an installer", prior.containsKey("handoff_file"))
        val sentinel = File(context.filesDir, "synthetic-updater-021-userdata.txt")
        assertEquals("Raiun updater 0.2.1 retained data\n", sentinel.readText())
        assertFalse(
            "Seed the old host with unknown-source installation denied",
            context.packageManager.canRequestPackageInstalls(),
        )

        val manager = UpdateManager.get(context, config)
        manager.initialize()
        val restored =
            runBlocking {
                withTimeout(15_000) { manager.state.first { it.ready || it.error != null } }
            }
        assertTrue("Ready restoration failed: ${restored.error}", restored.ready)
        assertEquals(prior["ready_tag"], restored.available?.tag)
        assertEquals(AndroidUpdateChannel.BETA, restored.channel)
        assertFalse(restored.automaticChecks)
        assertFalse(restored.wifiDownload)
        assertFalse(restored.offer)
        assertEquals(prior, prefs.all)
        assertEquals(installedVersionCode(context), bootstrap.all["host_version_code"])

        // The new bootstrap can reconstruct a manager after losing its process singleton.
        val clear =
            UpdateManager.Companion.javaClass.declaredMethods.single {
                it.name.startsWith("clearProcessInstanceForTests")
            }
        clear.apply { isAccessible = true }.invoke(UpdateManager.Companion)
        val recreated = workerManager(context)
        assertNotNull(recreated)
        assertEquals(config, requireNotNull(recreated).config)
        assertEquals(AndroidUpdateChannel.BETA, recreated.state.value.channel)
        assertFalse(recreated.state.value.automaticChecks)
        assertFalse(recreated.state.value.wifiDownload)
        assertEquals(prior, prefs.all)
        assertFalse(context.packageManager.canRequestPackageInstalls())
        assertEquals("Raiun updater 0.2.1 retained data\n", sentinel.readText())
        // No prepareInstall/startActivity call occurs: registration and restoration cannot grant consent.
    }

    private fun config() =
        UpdateConfig(
            owner = "phillip9933",
            repository = "raiun",
            tagPrefix = "android-v",
            assetPrefix = "raiun-android-",
            legacyVersions = setOf("0.9.3"),
            legacyAssetPrefix = "raiun-",
            stateName = "android_updates_synthetic_021_to_100",
        )

    private fun assertDisposable(context: Context) {
        assertEquals("app.raiun.cloud", context.packageName)
        assertTrue(
            Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
                Build.PRODUCT.startsWith("sdk", ignoreCase = true),
        )
    }

    private fun workerManager(context: Context): UpdateManager? {
        val method =
            UpdateManager.Companion.javaClass.declaredMethods.single {
                it.name.startsWith("getForWorker") && it.parameterTypes.contentEquals(arrayOf(Context::class.java))
            }
        return method.apply { isAccessible = true }.invoke(UpdateManager.Companion, context) as UpdateManager?
    }

    @Suppress("DEPRECATION")
    private fun installedVersionCode(context: Context): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
    }
}
