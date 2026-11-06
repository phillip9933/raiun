package eu.opencloud.android.next.feature.shares

import androidx.activity.ComponentActivity
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.core.sync.SharedFolderRequest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.annotation.GraphicsMode
import org.robolectric.annotation.SQLiteMode

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 35])
// Route/admission assertions do not cover native rasterization, fonts or SQLite behavior.
@GraphicsMode(GraphicsMode.Mode.LEGACY)
@SQLiteMode(SQLiteMode.Mode.LEGACY)
class IncomingShortcutApplicationTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun sharedRouteRejectsStaleIdAndAcknowledgesEachAdmittedSameFolderDelivery() {
        AppLock(compose.activity)
            .preferences
            .edit()
            .clear()
            .commit()
        val folder = SharedFolderRequest("synthetic-launch-account", "share", "scope", "remote", "/synthetic-folder")
        var requestId by mutableLongStateOf(1L)
        var admittedId = 2L
        val acknowledged = mutableListOf<Long>()
        compose.setContent {
            val id = requestId
            OpenCloudTheme {
                // No saved account exists: page loading fails locally before HTTP. Exercise the
                // real route/controller handoff independently from live server authorization.
                IncomingBrowserRoute(
                    account = folder.account,
                    initialFolder = folder,
                    onConsumeInitialFolder = { acknowledged += id },
                    initialFolderRequestId = id,
                    canApplyInitialFolder = { admittedId == id },
                )
            }
        }
        compose.runOnIdle { assertEquals(emptyList<Long>(), acknowledged) }
        compose.onNodeWithText("synthetic-folder").assertDoesNotExist()
        compose.runOnIdle { requestId = 2L }
        compose.runOnIdle { assertEquals(listOf(2L), acknowledged) }
        compose.onNodeWithText("synthetic-folder").assertExists()
        compose.runOnIdle {
            admittedId = 4L
            requestId = 3L
        }
        compose.runOnIdle { assertEquals(listOf(2L), acknowledged) }
        compose.runOnIdle { requestId = 4L }
        compose.runOnIdle { assertEquals(listOf(2L, 4L), acknowledged) }
        compose.onNodeWithText("synthetic-folder").assertExists()
    }
}
