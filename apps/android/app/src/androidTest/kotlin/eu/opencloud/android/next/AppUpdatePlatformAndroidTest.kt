package eu.opencloud.android.next

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.FileProvider
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Checks the updater's merged Android components and native archive parser on real API levels. */
class AppUpdatePlatformAndroidTest {
    @Test fun updateProviderOnlyServesItsPrivateCacheDirectory() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val authority = "${context.packageName}.android-updates"
        val provider =
            context.packageManager.getProviderInfo(
                android.content.ComponentName(
                    context.packageName,
                    "io.github.phillip9933.appupdater.UpdateFileProvider",
                ),
                PackageManager.GET_META_DATA,
            )
        assertEquals(authority, provider.authority)
        assertFalse(provider.exported)
        assertTrue(provider.grantUriPermissions)

        val updateDir = File(context.cacheDir, "updates").apply { mkdirs() }
        val allowed = File.createTempFile("native-update-provider-", ".apk", updateDir)
        val deniedCacheFile = File.createTempFile("native-update-outside-", ".apk", context.cacheDir)
        val deniedPrivateFile = File.createTempFile("native-update-private-", ".apk", context.filesDir)
        try {
            val contents = "synthetic update bytes".toByteArray()
            allowed.writeBytes(contents)
            val uri = FileProvider.getUriForFile(context, authority, allowed)
            assertEquals("content", uri.scheme)
            assertEquals(authority, uri.authority)
            context.contentResolver.openInputStream(uri).use { input ->
                assertNotNull(input)
                assertArrayEquals(contents, requireNotNull(input).readBytes())
            }
            assertThrows(IllegalArgumentException::class.java) {
                FileProvider.getUriForFile(context, authority, deniedCacheFile)
            }
            assertThrows(IllegalArgumentException::class.java) {
                FileProvider.getUriForFile(context, authority, deniedPrivateFile)
            }
        } finally {
            allowed.delete()
            deniedCacheFile.delete()
            deniedPrivateFile.delete()
        }
    }

    @Test fun packageManagerReadsTheInstalledApkSigningIdentityFromItsArchive() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val packageManager = context.packageManager
        val installed =
            if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getPackageInfo(
                    context.packageName,
                    PackageManager.PackageInfoFlags.of(
                        (PackageManager.GET_SIGNING_CERTIFICATES or PackageManager.GET_PERMISSIONS).toLong(),
                    ),
                )
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageInfo(context.packageName, signingFlags() or PackageManager.GET_PERMISSIONS)
            }
        val archive =
            if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getPackageArchiveInfo(
                    installed.applicationInfo!!.sourceDir,
                    PackageManager.PackageInfoFlags.of(PackageManager.GET_SIGNING_CERTIFICATES.toLong()),
                )
            } else {
                @Suppress("DEPRECATION")
                packageManager.getPackageArchiveInfo(installed.applicationInfo!!.sourceDir, signingFlags())
            }
        assertNotNull("Android must parse the installed APK as an archive", archive)
        assertEquals(context.packageName, archive!!.packageName)
        assertTrue("The installed APK needs a signing identity", signingBytes(installed).isNotEmpty())
        assertEquals(signingBytes(installed), signingBytes(archive))
        assertTrue(
            "The app must request the unknown-sources install permission",
            installed.requestedPermissions?.contains(Manifest.permission.REQUEST_INSTALL_PACKAGES) == true,
        )
    }

    @Suppress("DEPRECATION")
    private fun signingFlags(): Int =
        if (Build.VERSION.SDK_INT >= 28) PackageManager.GET_SIGNING_CERTIFICATES else PackageManager.GET_SIGNATURES

    @Suppress("DEPRECATION")
    private fun signingBytes(info: android.content.pm.PackageInfo): Set<List<Byte>> =
        if (Build.VERSION.SDK_INT >= 28) {
            info.signingInfo
                ?.apkContentsSigners
                ?.map { it.toByteArray().toList() }
                .orEmpty()
                .toSet()
        } else {
            info.signatures
                ?.map { it.toByteArray().toList() }
                .orEmpty()
                .toSet()
        }
}
