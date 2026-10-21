package eu.opencloud.android.next

import android.content.ClipData
import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import eu.opencloud.android.next.core.ui.PreparedExternalFile
import eu.opencloud.android.next.core.ui.externalFileChooser
import eu.opencloud.android.next.core.ui.rememberExternalFileLauncher
import kotlinx.coroutines.CompletableDeferred
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ExternalFileLauncherTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun duplicateTapsWaitForOnePreparationBeforeLaunching() {
        val ready = CompletableDeferred<Unit>()
        var prepared = 0
        var opened = 0
        compose.setContent {
            val launch = rememberExternalFileLauncher { throw AssertionError(it) }
            Button(onClick = {
                launch {
                    prepared++
                    ready.await()
                    PreparedExternalFile(Intent("test.OPEN")) { opened++ }
                }
            }) { Text("Open") }
        }
        compose.onNodeWithText("Open").performClick().performClick()
        compose.runOnIdle {
            assertEquals(1, prepared)
            assertNull(shadowOf(compose.activity).nextStartedActivity)
            ready.complete(Unit)
        }
        compose.waitForIdle()
        assertEquals("test.OPEN", shadowOf(compose.activity).nextStartedActivity.action)
        assertEquals(1, opened)
    }

    @Test fun leavingBrowserDoesNotLaunchAnAppWhenItsDownloadFinishes() {
        val visible = mutableStateOf(true)
        val ready = CompletableDeferred<Unit>()
        var errors = 0
        compose.setContent {
            if (visible.value) {
                val launch = rememberExternalFileLauncher { errors++ }
                Button(onClick = {
                    launch {
                        ready.await()
                        PreparedExternalFile(Intent("test.OPEN"))
                    }
                }) { Text("Open") }
            }
        }
        compose.onNodeWithText("Open").performClick()
        compose.runOnIdle { visible.value = false }
        compose.waitForIdle()
        compose.runOnIdle { ready.complete(Unit) }
        compose.waitForIdle()
        assertNull(shadowOf(compose.activity).nextStartedActivity)
        assertEquals(0, errors)
    }

    @Test fun chooserPreservesReadAccessAndStreamForEitherBrowser() {
        val uri = Uri.parse("content://test/file")
        val view =
            Intent(Intent.ACTION_VIEW).apply {
                data = uri
                clipData = ClipData.newRawUri("File", uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
        val chooser = externalFileChooser(view)
        assertEquals(Intent.ACTION_CHOOSER, chooser.action)
        assertEquals(uri, chooser.clipData?.getItemAt(0)?.uri)
        assertEquals(Intent.FLAG_GRANT_READ_URI_PERMISSION, chooser.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION)
    }
}
