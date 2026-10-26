package eu.opencloud.android.next

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import io.github.phillip9933.appupdater.AndroidUpdateRelease
import io.github.phillip9933.appupdater.UpdateConfig
import io.github.phillip9933.appupdater.UpdateManager
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.security.MessageDigest

/** Opt-in, disposable-emulator journey: the host confirms Android's installer and checks retained data. */
class AppUpdateInstallJourneyAndroidTest {
    @Test fun handVerifiedSyntheticApkToSystemInstaller() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        assumeTrue(
            "Synthetic upgrade runs only with the explicit runSyntheticUpgrade argument",
            InstrumentationRegistry.getArguments().getString("runSyntheticUpgrade") == "true",
        )
        val context = instrumentation.targetContext
        assertEquals("app.raiun.cloud", context.packageName)
        assertTrue(
            "Run this destructive upgrade journey only on a disposable Android emulator",
            Build.FINGERPRINT.contains("generic", ignoreCase = true) ||
                Build.PRODUCT.startsWith("sdk", ignoreCase = true),
        )
        assertEquals(
            "The journey starts from this debug build",
            BuildConfig.VERSION_CODE.toLong(),
            installedVersionCode(context),
        )
        assertTrue(context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        assertTrue(
            "Enable Install unknown apps for Raiun in Android Settings before running this journey",
            context.packageManager.canRequestPackageInstalls(),
        )

        val config =
            UpdateConfig(
                owner = "phillip9933",
                repository = "raiun",
                tagPrefix = "android-v",
                assetPrefix = "raiun-android-",
                legacyVersions = setOf("0.9.3"),
                legacyAssetPrefix = "raiun-",
                stateName = "android_updates_synthetic_install_journey",
            )
        val bootstrap = context.getSharedPreferences("io.github.phillip9933.appupdater.bootstrap", Context.MODE_PRIVATE)
        assertTrue(
            "Use a fresh disposable app install so this test cannot replace existing updater state",
            bootstrap.all.isEmpty() || bootstrap.getString("state_name", null) == config.stateName,
        )
        val asset = "updater/valid-higher.apk"
        val fixture = File.createTempFile("synthetic-upgrade-", ".apk", context.cacheDir)
        try {
            instrumentation.context.assets.open(asset).use { input ->
                fixture.outputStream().use { input.copyTo(it) }
            }
            val digest = sha256(fixture)
            val release =
                AndroidUpdateRelease(
                    tag = "android-v99.0.0",
                    notes = "Synthetic local installer journey",
                    assetName = "raiun-android-99.0.0.apk",
                    downloadUrl =
                        "https://github.com/phillip9933/raiun/releases/download/" +
                            "android-v99.0.0/raiun-android-99.0.0.apk",
                    sizeBytes = fixture.length(),
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
                    .putString("channel", "STABLE")
                    .putString("release_channel", "STABLE")
                    .putString("release_tag", release.tag)
                    .putString("release_notes", release.notes)
                    .putString("release_asset", release.assetName)
                    .putString("release_url", release.downloadUrl)
                    .putLong("release_size", release.sizeBytes)
                    .putString("release_sha", digest)
                    .putString("ready_tag", release.tag)
                    .putString("ready_sha", digest)
                    .commit(),
            )

            val manager = UpdateManager.get(context, config)
            val cachedApk = cachedApk(manager, release, digest)
            assertEquals(File(context.cacheDir, "updates"), cachedApk.parentFile)
            assertTrue(cachedApk.parentFile?.isDirectory == true || cachedApk.parentFile?.mkdirs() == true)
            fixture.copyTo(cachedApk, overwrite = true)
            val sentinel = File(context.filesDir, "synthetic-updater-userdata.txt")
            sentinel.writeText("Raiun synthetic upgrade retains user data\n")

            manager.initialize()
            val restored =
                runBlocking {
                    withTimeout(15_000) { manager.state.first { it.ready || it.error != null } }
                }
            assertTrue("Ready restoration failed: ${restored.error}", restored.ready)
            val installIntent = runBlocking { manager.prepareInstall() }
            assertNotNull("The manager did not prepare a verified installer Intent", installIntent)
            val intent = requireNotNull(installIntent)
            assertEquals(Intent.ACTION_VIEW, intent.action)
            assertEquals("content", intent.data?.scheme)
            assertEquals("${context.packageName}.android-updates", intent.data?.authority)
            assertTrue(intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)

            val status = File(context.filesDir, "synthetic-updater-install-status.json")

            fun writeStatus(phase: String) {
                status.writeText(
                    JSONObject()
                        .put("phase", phase)
                        .put("fromVersionCode", BuildConfig.VERSION_CODE)
                        .put("expectedVersionCode", BuildConfig.VERSION_CODE + 1)
                        .put("fixtureSha256", digest)
                        .put("sentinelFile", sentinel.name)
                        .put("cachedApk", cachedApk.name)
                        .toString(),
                )
            }
            writeStatus("prepared")
            context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            writeStatus("installer_launched")
            // Keep the instrumented app alive until PackageInstaller has read the provider URI.
            // The host confirms the update only after this test reports a visible system prompt.
            var confirmationVisible = false
            var lastInstallerText = ""
            val deadline = SystemClock.uptimeMillis() + 20_000
            while (!confirmationVisible && SystemClock.uptimeMillis() < deadline) {
                val window = instrumentation.uiAutomation.rootInActiveWindow
                if (window?.packageName?.toString()?.contains("packageinstaller") == true) {
                    confirmationVisible =
                        listOf("Install", "INSTALL", "Update")
                            .flatMap(window::findAccessibilityNodeInfosByText)
                            .any {
                                (
                                    it.text?.toString()?.equals("install", ignoreCase = true) == true ||
                                        it.text?.toString()?.equals("update", ignoreCase = true) == true
                                ) &&
                                    it.isEnabled &&
                                    it.isClickable
                            }
                    lastInstallerText =
                        if (window
                                .findAccessibilityNodeInfosByText(
                                    "There was a problem parsing the package",
                                ).isNotEmpty()
                        ) {
                            "PackageInstaller rejected the staged APK"
                        } else {
                            "PackageInstaller appeared without an enabled Install or Update button"
                        }
                    if (lastInstallerText.startsWith("PackageInstaller rejected")) break
                }
                SystemClock.sleep(250)
            }
            assertTrue(lastInstallerText.ifEmpty { "System PackageInstaller did not appear" }, confirmationVisible)
            writeStatus("installer_confirmation_visible")
        } finally {
            fixture.delete()
        }
    }

    private fun cachedApk(
        manager: UpdateManager,
        release: AndroidUpdateRelease,
        digest: String,
    ): File {
        val method =
            manager.javaClass.declaredMethods.single {
                it.name.startsWith("apkFile") &&
                    it.parameterTypes.contentEquals(arrayOf(AndroidUpdateRelease::class.java, String::class.java))
            }
        return method.apply { isAccessible = true }.invoke(manager, release, digest) as File
    }

    @Suppress("DEPRECATION")
    private fun installedVersionCode(context: Context): Long {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        return if (Build.VERSION.SDK_INT >= 28) info.longVersionCode else info.versionCode.toLong()
    }

    private fun sha256(file: File): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }
}
