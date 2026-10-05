package eu.opencloud.android.next

import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.annotation.MainThread
import eu.opencloud.android.next.core.security.AppLock
import java.util.WeakHashMap

/** Combines app-lock privacy with temporary sensitive screens without clearing another owner's flag. */
internal object SensitiveWindowProtection {
    private val leases = WeakHashMap<ComponentActivity, Int>()

    @MainThread
    fun acquire(activity: ComponentActivity): () -> Unit {
        leases[activity] = (leases[activity] ?: 0) + 1
        update(activity)
        var released = false
        return {
            if (!released) {
                released = true
                val remaining = (leases[activity] ?: 1) - 1
                if (remaining == 0) leases.remove(activity) else leases[activity] = remaining
                update(activity)
            }
        }
    }

    @MainThread
    fun update(activity: ComponentActivity) {
        if (AppLock(activity).enabled || (leases[activity] ?: 0) > 0) {
            activity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        } else {
            activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }
    }
}
