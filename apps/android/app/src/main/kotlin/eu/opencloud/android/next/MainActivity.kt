package eu.opencloud.android.next

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.toArgb
import androidx.core.view.WindowCompat
import eu.opencloud.android.next.core.datastore.Appearance
import eu.opencloud.android.next.core.datastore.SettingsRepository
import eu.opencloud.android.next.core.datastore.UserSettings
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudColor
import eu.opencloud.android.next.core.designsystem.theme.OpenCloudTheme
import eu.opencloud.android.next.ui.OpenCloudNextApp

class MainActivity : AppCompatActivity() {
    private var oauthCallback by mutableStateOf<String?>(null)
    private var folderShortcut by mutableStateOf<String?>(null)

    override fun onResume() {
        super.onResume()
        restoreStoredTaskAppearance()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        applyStoredWindowTheme()
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), NOTIFICATION_PERMISSION_REQUEST)
        }
        acceptLaunchIntent(intent)

        setContent {
            val repository = SettingsRepository.create(this)
            val settings by repository.settings.collectAsState(UserSettings())
            LaunchedEffect(repository) {
                repository.settings.collect { value ->
                    getSharedPreferences("window-appearance", MODE_PRIVATE)
                        .edit()
                        .putString("appearance", value.appearance.name)
                        .apply()
                }
            }
            val dark =
                when (settings.appearance) {
                    Appearance.SYSTEM -> isSystemInDarkTheme()
                    Appearance.LIGHT -> false
                    Appearance.DARK -> true
                }
            SideEffect {
                val barStyle =
                    if (dark) {
                        SystemBarStyle.dark(OpenCloudColor.Transparent.toArgb())
                    } else {
                        SystemBarStyle.light(OpenCloudColor.Transparent.toArgb(), OpenCloudColor.Transparent.toArgb())
                    }
                enableEdgeToEdge(statusBarStyle = barStyle, navigationBarStyle = barStyle)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) window.isNavigationBarContrastEnforced = false
                WindowCompat.getInsetsController(window, window.decorView).apply {
                    isAppearanceLightStatusBars = !dark
                    isAppearanceLightNavigationBars = !dark
                }
            }
            OpenCloudTheme(darkTheme = dark) {
                val background =
                    androidx.compose.material3.MaterialTheme.colorScheme.background
                        .toArgb()
                SideEffect { updateTaskBackground(dark, background) }
                DeviceLockGate(this) {
                    OpenCloudNextApp(
                        oauthCallback = oauthCallback,
                        folderShortcut = folderShortcut,
                        onConsumeFolderShortcut = { folderShortcut = null },
                    )
                }
            }
        }
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        acceptLaunchIntent(intent)
    }

    private fun acceptLaunchIntent(intent: android.content.Intent?) {
        val folder = intent?.data?.scheme == eu.opencloud.android.next.core.sync.FolderShortcutTarget.SCHEME
        folderShortcut = intent?.dataString?.takeIf { folder }
        oauthCallback = intent?.dataString?.takeUnless { folder }
    }

    private companion object {
        const val NOTIFICATION_PERMISSION_REQUEST = 1001
    }
}
