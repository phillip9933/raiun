package eu.opencloud.android.next

import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.annotation.RequiresApi
import androidx.test.filters.SdkSuppress
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import eu.opencloud.android.next.core.network.OpenCloudError
import eu.opencloud.android.next.core.network.safeMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/** Real framework caller snapshot, with an external provider and a receiver-only persisted grant. */
@RequiresApi(35)
@SdkSuppress(minSdkVersion = 35)
class IncomingShareProvenanceAndroidTest {
    @Test fun persistedReceiverPermissionDoesNotAuthorizeAnUnrelatedLaunchCaller() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val resolver = context.contentResolver
        val uri = Uri.parse("content://$FIXTURE_PACKAGE.documents/synthetic.dbf")
        val preferences = context.getSharedPreferences("app-lock", Context.MODE_PRIVATE)
        val wasEnabled = preferences.getBoolean("enabled", false)
        val batches = File(context.noBackupFilesDir, "incoming-shares").list().orEmpty().toSet()
        var installed = false
        var activity: IncomingShareActivity? = null
        try {
            NativeUiDiagnostics("incoming-provenance").prepareDevice()
            preferences.edit().putBoolean("enabled", false).commit()
            if (android.os.Build.VERSION.SDK_INT >= 33) {
                instrumentation.uiAutomation.grantRuntimePermission(
                    context.packageName,
                    android.Manifest.permission.POST_NOTIFICATIONS,
                )
            }
            // Missing generated assets fail the test; an SDK skip is the only expected omission.
            val bytes =
                instrumentation.context.assets
                    .open("share-provenance-fixture.apk")
                    .use { it.readBytes() }
            install(instrumentation, bytes)
            installed = true
            activity = launch(instrumentation, "am start -W -n $FIXTURE_PACKAGE/.GrantActivity")
            assertEquals(
                PackageManager.PERMISSION_GRANTED,
                requireNotNull(activity.caller).checkContentUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION),
            )
            resolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            assertTrue(resolver.persistedUriPermissions.any { it.uri == uri && it.isReadPermission })
            assertEquals(
                "synthetic share provenance",
                resolver.openInputStream(uri)!!.bufferedReader().use { it.readText() },
            )
            val different = Uri.parse("content://$FIXTURE_PACKAGE.documents/unrelated.dbf")
            shell(
                instrumentation,
                "am start -W --activity-single-top " +
                    "-n ${context.packageName}/eu.opencloud.android.next.IncomingShareActivity " +
                    "-a android.intent.action.SEND -t application/octet-stream " +
                    "--eu android.intent.extra.STREAM $different",
            )
            instrumentation.waitForIdleSync()
            assertEquals(
                "Redelivery must leave the original batch intact",
                listOf(uri),
                incomingShareUris(activity.intent),
            )
            val original = activity
            instrumentation.runOnMainSync { original.recreate() }
            activity = awaitResumedShare(instrumentation, original)
            assertEquals(
                PackageManager.PERMISSION_GRANTED,
                requireNotNull(activity.caller).checkContentUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION),
            )
            close(instrumentation, activity)
            activity = null
            // Shell has no provider grant. No grant flag is supplied, so the existing receiver
            // permission allows the launch but must not make the sender's launch snapshot pass.
            activity =
                launch(
                    instrumentation,
                    "am start -W -n ${context.packageName}/eu.opencloud.android.next.IncomingShareActivity " +
                        "-a android.intent.action.SEND -t application/octet-stream " +
                        "--eu android.intent.extra.STREAM $uri " +
                        "--es android.intent.extra.REFERRER_NAME android-app://$FIXTURE_PACKAGE",
                )
            assertEquals(
                PackageManager.PERMISSION_DENIED,
                requireNotNull(activity.caller).checkContentUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION),
            )
            // Receiver readability survives the denied launch; denial is sender scoped.
            assertEquals(
                "synthetic share provenance",
                resolver.openInputStream(uri)!!.bufferedReader().use { it.readText() },
            )
            awaitDeniedScreen(instrumentation, context)
            val denied = activity
            instrumentation.runOnMainSync { denied.recreate() }
            activity = awaitResumedShare(instrumentation, denied)
            assertEquals(
                PackageManager.PERMISSION_DENIED,
                requireNotNull(activity.caller).checkContentUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION),
            )
            awaitDeniedScreen(instrumentation, context)
            assertEquals(batches, File(context.noBackupFilesDir, "incoming-shares").list().orEmpty().toSet())
        } finally {
            activity?.let { close(instrumentation, it) }
            if (resolver.persistedUriPermissions.any { it.uri == uri }) {
                resolver.releasePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            if (installed) assertTrue(shell(instrumentation, "pm uninstall $FIXTURE_PACKAGE").contains("Success"))
            preferences.edit().putBoolean("enabled", wasEnabled).commit()
        }
    }

    private fun install(
        instrumentation: Instrumentation,
        bytes: ByteArray,
    ) {
        val descriptors = instrumentation.uiAutomation.executeShellCommandRw("pm install -r -t -S ${bytes.size}")
        ParcelFileDescriptor.AutoCloseOutputStream(descriptors[1]).use { it.write(bytes) }
        val result = ParcelFileDescriptor.AutoCloseInputStream(descriptors[0]).bufferedReader().use { it.readText() }
        assertTrue("Synthetic fixture install must succeed: $result", result.contains("Success"))
    }

    private fun launch(
        instrumentation: Instrumentation,
        command: String,
    ): IncomingShareActivity {
        val monitor = instrumentation.addMonitor(IncomingShareActivity::class.java.name, null, false)
        return try {
            val result = shell(instrumentation, command)
            assertFalse("Synthetic launch failed: $result", result.contains("Error:"))
            val activity = monitor.waitForActivityWithTimeout(8_000)
            assertNotNull("The synthetic launch must reach the real incoming-share Activity", activity)
            instrumentation.waitForIdleSync()
            activity as IncomingShareActivity
        } finally {
            instrumentation.removeMonitor(monitor)
        }
    }

    private fun awaitResumedShare(
        instrumentation: Instrumentation,
        original: IncomingShareActivity,
    ): IncomingShareActivity {
        val deadline = SystemClock.uptimeMillis() + 8_000
        var recreated: IncomingShareActivity? = null
        while (recreated == null && SystemClock.uptimeMillis() < deadline) {
            instrumentation.runOnMainSync {
                recreated =
                    ActivityLifecycleMonitorRegistry
                        .getInstance()
                        .getActivitiesInStage(Stage.RESUMED)
                        .filterIsInstance<IncomingShareActivity>()
                        .firstOrNull { it !== original }
            }
            if (recreated == null) SystemClock.sleep(50)
        }
        assertNotNull("A recreated incoming-share Activity must resume", recreated)
        return requireNotNull(recreated)
    }

    private fun awaitDeniedScreen(
        instrumentation: Instrumentation,
        context: Context,
    ) {
        val error = OpenCloudError.SourcePermissionDenied.safeMessage(context)
        val deadline = SystemClock.uptimeMillis() + 5_000
        while (!containsText(instrumentation.uiAutomation.rootInActiveWindow, error) &&
            SystemClock.uptimeMillis() < deadline
        ) {
            SystemClock.sleep(50)
        }
        assertTrue(
            "Denied sender must show the permission error",
            containsText(instrumentation.uiAutomation.rootInActiveWindow, error),
        )
    }

    private fun containsText(
        node: AccessibilityNodeInfo?,
        text: String,
    ): Boolean =
        node != null &&
            (node.text?.toString() == text || (0 until node.childCount).any { containsText(node.getChild(it), text) })

    private fun close(
        instrumentation: Instrumentation,
        activity: IncomingShareActivity,
    ) {
        instrumentation.runOnMainSync { activity.finish() }
        instrumentation.waitForIdleSync()
    }

    private fun shell(
        instrumentation: Instrumentation,
        command: String,
    ): String =
        ParcelFileDescriptor
            .AutoCloseInputStream(
                instrumentation.uiAutomation.executeShellCommand(command),
            ).bufferedReader()
            .use {
                it.readText()
            }

    private companion object {
        const val FIXTURE_PACKAGE = "app.raiun.test.shareprovenance"
    }
}
