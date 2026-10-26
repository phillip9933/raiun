package eu.opencloud.android.next

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import io.github.phillip9933.appupdater.AndroidUpdateRelease
import io.github.phillip9933.appupdater.UpdateConfig
import io.github.phillip9933.appupdater.UpdateError
import io.github.phillip9933.appupdater.UpdatePolicy
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.xmlpull.v1.XmlPullParser
import java.io.File
import java.io.RandomAccessFile
import java.security.MessageDigest

/** Exercises the library verifier against PackageManager's real APK archive and signature parsing. */
class AppUpdateVerificationAndroidTest {
    private val context: Context
        get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun higherVersionWithInstalledSignerIsAccepted() {
        withFixture("valid-higher.apk") { file, release ->
            assertNull(verify(file, release, requireNotNull(release.sha256)))
        }
    }

    @Test fun differentSignerIsRejected() {
        assertFixtureError("wrong-signer.apk", UpdateError.SIGNATURE_MISMATCH)
    }

    @Test fun differentPackageIsRejected() {
        assertFixtureError("wrong-package.apk", UpdateError.WRONG_PACKAGE)
    }

    @Test fun nonIncreasingVersionIsRejected() {
        assertFixtureError("old-version.apk", UpdateError.OLD_VERSION)
    }

    @Suppress("DEPRECATION")
    @Test
    fun debuggableArchiveIsRejected() {
        withFixture("debuggable.apk") { file, release ->
            val signingFlags =
                if (Build.VERSION.SDK_INT >= 28) {
                    PackageManager.GET_SIGNING_CERTIFICATES
                } else {
                    PackageManager.GET_SIGNATURES
                }
            val archive = archiveInfo(file, signingFlags)
            val broadArchive =
                archiveInfo(
                    file,
                    signingFlags or PackageManager.GET_META_DATA or PackageManager.GET_PERMISSIONS,
                )
            val manifestDebuggable = runCatching { archiveManifestDebuggable(file, requireNotNull(archive)) }
            val diagnostic =
                "SDK=${Build.VERSION.SDK_INT}; signingFlags=${archive?.applicationInfo?.flags}; " +
                    "broadFlags=${broadArchive?.applicationInfo?.flags}; " +
                    "debugBit=${ApplicationInfo.FLAG_DEBUGGABLE}; " +
                    "archivePackage=${archive?.packageName}; minSdk=${archive?.applicationInfo?.minSdkVersion}; " +
                    "manifestDebuggable=${manifestDebuggable.getOrElse { it.javaClass.simpleName }}"
            assertEquals(diagnostic, UpdateError.DEBUG_APK, verify(file, release, requireNotNull(release.sha256)))
        }
    }

    @Test fun alteredBytesAndWrongExpectedHashAreRejectedBeforePackageParsing() {
        withFixture("valid-higher.apk") { file, release ->
            assertEquals(UpdateError.HASH_MISMATCH, verify(file, release, "0".repeat(64)))
            RandomAccessFile(file, "rw").use { archive ->
                val firstByte = archive.readUnsignedByte()
                archive.seek(0)
                archive.writeByte(firstByte xor 0x01)
            }
            assertEquals(UpdateError.HASH_MISMATCH, verify(file, release, requireNotNull(release.sha256)))
        }
    }

    @Test fun truncatedArchiveIsRejectedBeforePackageParsing() {
        withFixture("valid-higher.apk") { file, release ->
            file.outputStream().use { it.write(0) }
            assertEquals(UpdateError.SIZE_MISMATCH, verify(file, release, requireNotNull(release.sha256)))
        }
    }

    private fun assertFixtureError(
        name: String,
        expected: UpdateError,
    ) {
        withFixture(name) { file, release ->
            assertEquals(expected, verify(file, release, requireNotNull(release.sha256)))
        }
    }

    private fun withFixture(
        name: String,
        check: (File, AndroidUpdateRelease) -> Unit,
    ) {
        val file = File.createTempFile("native-update-verification-", ".apk", context.cacheDir)
        try {
            InstrumentationRegistry.getInstrumentation().context.assets.open("updater/$name").use { input ->
                file.outputStream().use { input.copyTo(it) }
            }
            val release =
                AndroidUpdateRelease(
                    tag = "android-v99.0.0",
                    notes = "Synthetic native verifier test",
                    assetName = "raiun-android-99.0.0.apk",
                    downloadUrl =
                        "https://github.com/phillip9933/raiun/releases/download/" +
                            "android-v99.0.0/raiun-android-99.0.0.apk",
                    sizeBytes = file.length(),
                    sha256 = sha256(file),
                    publishedAt = null,
                )
            check(file, release)
        } finally {
            file.delete()
        }
    }

    private fun verify(
        file: File,
        release: AndroidUpdateRelease,
        expectedHash: String,
    ): UpdateError? {
        val config =
            UpdateConfig(
                owner = "phillip9933",
                repository = "raiun",
                tagPrefix = "android-v",
                assetPrefix = "raiun-android-",
                legacyVersions = setOf("0.9.3"),
                legacyAssetPrefix = "raiun-",
            )
        val verifierClass = Class.forName("io.github.phillip9933.appupdater.UpdateApkVerifier")
        val verifier =
            verifierClass
                .getDeclaredConstructor(Context::class.java, UpdatePolicy::class.java)
                .apply { isAccessible = true }
                .newInstance(context, UpdatePolicy(config))
        val method =
            verifierClass.declaredMethods.single {
                it.name.startsWith("verify") &&
                    it.parameterTypes.contentEquals(
                        arrayOf(File::class.java, AndroidUpdateRelease::class.java, String::class.java),
                    )
            }
        return method.apply { isAccessible = true }.invoke(verifier, file, release, expectedHash) as UpdateError?
    }

    private fun sha256(file: File): String =
        MessageDigest
            .getInstance("SHA-256")
            .digest(file.readBytes())
            .joinToString("") { "%02x".format(it) }

    @Suppress("DEPRECATION")
    private fun archiveInfo(
        file: File,
        flags: Int,
    ): PackageInfo? =
        if (Build.VERSION.SDK_INT >= 33) {
            context.packageManager.getPackageArchiveInfo(
                file.absolutePath,
                PackageManager.PackageInfoFlags.of(flags.toLong()),
            )
        } else {
            context.packageManager.getPackageArchiveInfo(file.absolutePath, flags)
        }

    private fun archiveManifestDebuggable(
        file: File,
        info: PackageInfo,
    ): Boolean {
        val archiveApplication =
            ApplicationInfo(requireNotNull(info.applicationInfo)).apply {
                sourceDir = file.absolutePath
                publicSourceDir = file.absolutePath
            }
        val resources = context.packageManager.getResourcesForApplication(archiveApplication)
        val parser = resources.assets.openXmlResourceParser("AndroidManifest.xml")
        try {
            while (parser.eventType != XmlPullParser.END_DOCUMENT) {
                if (parser.eventType == XmlPullParser.START_TAG && parser.name == "application") {
                    val namespace = "http://schemas.android.com/apk/res/android"
                    val id = parser.getAttributeResourceValue(namespace, "debuggable", 0)
                    return if (id !=
                        0
                    ) {
                        resources.getBoolean(id)
                    } else {
                        parser.getAttributeBooleanValue(namespace, "debuggable", false)
                    }
                }
                parser.next()
            }
            error("APK has no application manifest element")
        } finally {
            parser.close()
        }
    }
}
