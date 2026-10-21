package eu.opencloud.android.next

import android.content.Intent
import android.content.SharedPreferences
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import eu.opencloud.android.next.core.security.AppLock

@Composable
internal fun DeviceLockGate(
    activity: ComponentActivity,
    content: @Composable () -> Unit,
) {
    val lock = remember { AppLock(activity) }
    var allowed by remember { mutableStateOf(lock.canOpenApp()) }
    var promptInFlight by rememberSaveable { mutableStateOf(false) }
    var attemptedThisVisit by rememberSaveable { mutableStateOf(false) }
    var resumed by remember { mutableStateOf(activity.lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)) }
    val holder = rememberSaveableStateHolder()
    val launcher =
        rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            promptInFlight = false
            lock.foreground()
            allowed = lock.canOpenApp()
        }

    fun unlock() {
        if (promptInFlight || !lock.deviceSecure) return
        attemptedThisVisit = true
        promptInFlight = true
        launcher.launch(Intent(activity, DeviceUnlockActivity::class.java))
    }
    LaunchedEffect(allowed, resumed, attemptedThisVisit) {
        if (!allowed && resumed && !attemptedThisVisit) unlock()
    }
    DisposableEffect(activity) {
        fun update() {
            allowed = lock.canOpenApp()
            SensitiveWindowProtection.update(activity)
        }
        val observer =
            lockLifecycleObserver(activity, lock, ::update, { resumed = it }) {
                if (!promptInFlight) attemptedThisVisit = false
            }
        val receiver =
            object : android.content.BroadcastReceiver() {
                override fun onReceive(
                    context: android.content.Context,
                    intent: Intent,
                ) {
                    attemptedThisVisit = false
                    lock.lock()
                    update()
                }
            }
        androidx.core.content.ContextCompat.registerReceiver(
            activity,
            receiver,
            android.content.IntentFilter(Intent.ACTION_SCREEN_OFF),
            androidx.core.content.ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> update() }
        activity.lifecycle.addObserver(observer)
        lock.preferences.registerOnSharedPreferenceChangeListener(listener)
        update()
        onDispose {
            activity.unregisterReceiver(receiver)
            activity.lifecycle.removeObserver(observer)
            lock.preferences.unregisterOnSharedPreferenceChangeListener(listener)
        }
    }
    if (allowed) {
        holder.SaveableStateProvider("unlocked-app") { content() }
    } else {
        androidx.compose.material3.Surface(Modifier.fillMaxSize()) {
            Column(
                Modifier.fillMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
            ) {
                Text(stringResource(R.string.app_lock_title))
                if (!lock.deviceSecure) Text(stringResource(R.string.app_lock_setup_required))
                Button(onClick = {
                    unlock()
                }) {
                    Text(
                        stringResource(
                            if (lock.biometricEnabled) {
                                R.string.app_lock_unlock_biometric
                            } else {
                                R.string.app_lock_unlock_credentials
                            },
                        ),
                    )
                }
            }
        }
    }
}

private fun lockLifecycleObserver(
    activity: ComponentActivity,
    lock: AppLock,
    onChanged: () -> Unit,
    onResumed: (Boolean) -> Unit,
    onBackground: () -> Unit,
): LifecycleEventObserver =
    LifecycleEventObserver { _, event ->
        when (event) {
            Lifecycle.Event.ON_START -> {
                lock.foreground()
                onChanged()
            }
            Lifecycle.Event.ON_RESUME -> onResumed(true)
            Lifecycle.Event.ON_PAUSE -> onResumed(false)
            Lifecycle.Event.ON_STOP -> {
                if (!activity.isChangingConfigurations) {
                    onBackground()
                    lock.background()
                }
                onChanged()
            }
            else -> Unit
        }
    }
