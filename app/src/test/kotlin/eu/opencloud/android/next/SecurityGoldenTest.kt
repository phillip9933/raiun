package eu.opencloud.android.next

import android.Manifest
import android.app.KeyguardManager
import androidx.activity.ComponentActivity
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.lifecycle.Lifecycle
import com.github.takahirom.roborazzi.captureRoboImage
import eu.opencloud.android.next.core.datastore.PhotoMetadataPreferences
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.core.security.AppLock
import eu.opencloud.android.next.feature.files.PhotoMetadataPermissionDialog
import eu.opencloud.android.next.feature.settings.SecuritySettingsScreen
import eu.opencloud.android.next.feature.settings.SettingsScreen
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows
import org.robolectric.annotation.Config

@org.robolectric.annotation.GraphicsMode(org.robolectric.annotation.GraphicsMode.Mode.NATIVE)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35], qualifiers = "w360dp-h800dp")
class SecurityGoldenTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()

    @Test fun declinedPhotoMetadataChoicePersistsAndCanBeReenabled() {
        val preferences = PhotoMetadataPreferences(compose.activity)
        preferences.askForLocationPermission = false
        assertFalse(PhotoMetadataPreferences(compose.activity).askForLocationPermission)
        preferences.askForLocationPermission = true
        assertTrue(PhotoMetadataPreferences(compose.activity).askForLocationPermission)
    }

    @Test fun photoMetadataChoicesAreButtons() {
        var neverAskAgain: Boolean? = null
        compose.setContent {
            OpenCloudTheme {
                PhotoMetadataPermissionDialog(
                    denied = false,
                    onCancel = {},
                    onAllow = {},
                    onWithoutMetadata = { neverAskAgain = it },
                )
            }
        }
        compose.onNodeWithText("Grant permission").assertExists()
        compose.onRoot().captureRoboImage("src/test/snapshots/rendered/photo_metadata_permission.png")
        compose.onNodeWithText("Upload anyway (ask every time)").performClick()
        assertTrue(neverAskAgain == false)
        compose.onNodeWithText("Upload anyway (never ask again)").performClick()
        assertTrue(neverAskAgain == true)
    }

    @Test fun metadataPermissionStatusRefreshesAfterReturningFromSettings() {
        val app = compose.activity.application
        Shadows.shadowOf(app).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        compose.setContent { OpenCloudTheme { SettingsScreen(UserSettings(), {}, {}, {}) } }
        compose.onNodeWithText("Permissions").performScrollTo().performClick()
        compose.onNodeWithText("Allow photo location").assertExists()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        Shadows.shadowOf(app).grantPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Photo location access is allowed.").assertExists()
        compose.activityRule.scenario.moveToState(Lifecycle.State.CREATED)
        Shadows.shadowOf(app).denyPermissions(Manifest.permission.ACCESS_MEDIA_LOCATION)
        compose.activityRule.scenario.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Allow photo location").assertExists()
    }

    @Test fun securitySettingsExplainProtection() {
        val lock = AppLock(compose.activity)
        Shadows.shadowOf(compose.activity.getSystemService(KeyguardManager::class.java)).setIsDeviceSecure(true)
        lock.authenticated()
        lock.setEnabled(true)
        try {
            compose.setContent { OpenCloudTheme { SecuritySettingsScreen(onNavigateBack = {}) } }
            compose.onRoot().captureRoboImage("src/test/snapshots/rendered/security_settings.png")
        } finally {
            lock.preferences
                .edit()
                .clear()
                .commit()
            lock.lock()
        }
    }
}
